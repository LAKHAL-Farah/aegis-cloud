"""The supervised stack: how each component is started, stopped, probed and healed.

One place knows the command lines, so the watchdog's restart and the chaos harness's restart are the same code path:
what the experiment tests is what production would run.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from .probes import HeartbeatProbe, HttpProbe, pid_alive, read_heartbeat
from .watchdog import Healer


class Stack:
    def __init__(self, root: Path, *, endpoint: str = "http://localhost:4566", opensearch: str | None = None,
                 resume: bool = True, python: str = sys.executable, popen=subprocess.Popen, clock=time.time, sleep=time.sleep):
        self.root, self.endpoint, self.opensearch, self.resume = Path(root), endpoint, opensearch, resume
        self.python, self.popen, self.clock, self.sleep = python, popen, clock, sleep
        self.ops = self.root / "build" / "ops"
        self.hb = self.ops / "heartbeats"
        self.response_state = self.ops / "response"

    # ---- command lines (pure, unit-tested)
    def command(self, name: str) -> list[str]:
        if name == "detector":
            cmd = [self.python, str(self.root / "detections" / "detect.py"), "watch",
                   "--heartbeat-file", str(self.hb / "detector.json")]
            if self.opensearch:
                cmd += ["--opensearch", self.opensearch]
            if self.resume:
                cmd += ["--state-file", str(self.ops / "detector-state.json")]
            return cmd
        if name == "responder":
            cmd = [self.python, str(self.root / "response" / "respond.py"), "--endpoint", self.endpoint,
                   "--state-dir", str(self.response_state), "watch", "--execute", "--approver", "file",
                   "--heartbeat-file", str(self.hb / "responder.json")]
            if self.resume:
                cmd += ["--resume"]
            return cmd
        raise KeyError(name)

    # ---- probes
    def probes(self) -> list:
        out = [HttpProbe("localstack", f"{self.endpoint}/_localstack/health"),
               HeartbeatProbe("detector", self.hb / "detector.json", max_age_s=20),
               HeartbeatProbe("responder", self.hb / "responder.json", max_age_s=10)]
        if self.opensearch:
            out.append(HttpProbe("opensearch", f"{self.opensearch}/_cluster/health"))
        return out

    def probe(self, name: str):
        return next(p for p in self.probes() if p.component == name)

    # ---- lifecycle
    def pid(self, name: str) -> int | None:
        hb = read_heartbeat(self.hb / f"{name}.json")
        return int(hb["pid"]) if hb and pid_alive(hb["pid"]) else None

    def kill(self, name: str, sig=signal.SIGKILL) -> bool:
        pid = self.pid(name)
        if pid is None:
            return False
        os.kill(pid, sig)
        return True

    def start(self, name: str, timeout_s: float = 25.0) -> bool:
        """Start it (any stuck copy is killed first) and wait for the first fresh heartbeat."""
        self.kill(name)
        (self.hb / f"{name}.json").unlink(missing_ok=True)       # a stale file must not look like a fresh start
        self.ops.mkdir(parents=True, exist_ok=True)
        with (self.ops / f"{name}.log").open("ab") as log:
            self.popen(self.command(name), stdout=log, stderr=subprocess.STDOUT, cwd=self.root, start_new_session=True)
        end = self.clock() + timeout_s
        while self.clock() < end:
            if self.probe(name).check().up:
                return True
            self.sleep(0.5)
        return False

    def fresh_state(self, stamp: str) -> Path | None:
        """A clean start for one experiment. The detector's checkpoint is deleted (it must prime 'from now', not replay an
        earlier run) and the responder's state, ledger cooldowns included, is archived rather than deleted: it is
        evidence, and a left-over cooldown would make the next experiment's incident a 'duplicate'."""
        (self.ops / "detector-state.json").unlink(missing_ok=True)
        if not self.response_state.exists():
            return None
        dest = self.ops / "archive" / f"response-{stamp}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.response_state), str(dest))
        return dest

    def healers(self, **kw) -> dict:
        return {n: Healer(n, (lambda n=n: self.start(n)), **kw) for n in ("detector", "responder")}
