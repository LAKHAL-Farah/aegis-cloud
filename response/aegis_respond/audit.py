"""Append-only, hash-chained audit trail (JSON lines). Each record carries the hash of the one before it,
so an edited, removed or reordered line is detected by `verify`. It is tamper-EVIDENT, not tamper-proof: on real
AWS ship it to a bucket with Object Lock."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
SECRET_KEYS = ("secret", "token", "password", "authorization", "signature")


def scrub(value):
    """Drop anything that looks like key material before it reaches a log line."""
    if isinstance(value, dict):
        return {k: ("[redacted]" if any(s in str(k).lower() for s in SECRET_KEYS) else scrub(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]
    return value


def _digest(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path, mirror=None):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._mirror = mirror        # e.g. print: in Lambda, stdout is the durable copy (CloudWatch Logs)
        # fsync every record by default. Set AEGIS_AUDIT_FSYNC=0 only for tests: on /mnt/c under WSL one fsync costs ~100 ms.
        self._fsync = os.environ.get("AEGIS_AUDIT_FSYNC", "1") != "0"

    def _last_hash(self) -> tuple[str, int]:
        if not self.path.exists():
            return GENESIS, 0
        last, n = GENESIS, 0
        with self.path.open() as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    last, n = rec["hash"], rec["seq"]
        return last, n

    def append(self, incident: str, step: str, status: str, **data) -> dict:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            prev, n = self._last_hash()
            body = {"seq": n + 1, "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "incident": incident, "step": step, "status": status, "data": scrub(data), "prev": prev}
            rec = {**body, "hash": _digest(prev, body)}
            with self.path.open("a") as fh:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                fh.flush()
                if self._fsync:
                    os.fsync(fh.fileno())
            if self._mirror:
                self._mirror(json.dumps(rec, sort_keys=True))
            return rec

    def records(self, incident: str | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        out = [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]
        return [r for r in out if incident in (None, r["incident"])]

    def verify(self) -> tuple[bool, str]:
        prev, expect = GENESIS, 1
        for rec in self.records():
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec["seq"] != expect or rec["prev"] != prev or _digest(prev, body) != rec["hash"]:
                return False, f"chain broken at seq {rec['seq']}"
            prev, expect = rec["hash"], expect + 1
        return True, f"{expect - 1} records, chain intact"
