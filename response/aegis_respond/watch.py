"""Follow build/findings/ (the ASFF files the detector writes) and hand each new one to the responder."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def watch(responder, findings_dir: Path, stop: threading.Event, *, replay: bool = False, since: float | None = None,
          poll_s: float = 0.4, workers: int = 4, on_outcome=None) -> None:
    """New files only, unless replay=True (everything) or since=<epoch> (files modified at or after that time).
    One worker per incident, so a person taking a minute to tap Approve does not block the next finding."""
    findings_dir = Path(findings_dir)
    seen = set() if (replay or since is not None) else {p.name for p in findings_dir.glob("*.json")}

    def work(path: Path) -> None:
        try:
            finding = json.loads(path.read_text())
        except (OSError, ValueError) as exc:
            responder.audit.append("-", "rejected", "error", reason=f"{path.name}: {type(exc).__name__}")
            return
        out = responder.handle(finding)
        if on_outcome:
            on_outcome(path.name, out)

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="respond") as pool:
        while not stop.is_set():
            for p in sorted(findings_dir.glob("*.json")):
                if p.name in seen:
                    continue
                if since is not None and p.stat().st_mtime < since:
                    seen.add(p.name)
                    continue
                seen.add(p.name)
                pool.submit(work, p)
            stop.wait(poll_s)
