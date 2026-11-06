"""Follow build/findings/ (the ASFF files the detector writes) and hand each new one to the responder."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def watch(responder, findings_dir: Path, stop: threading.Event, *, replay: bool = False, since: float | None = None,
          poll_s: float = 0.4, workers: int = 4, on_outcome=None, resume: bool = False, on_tick=None,
          resume_max_age_s: float | None = None) -> None:
    """New files only, unless replay=True (everything), since=<epoch> (files modified at or after that time) or
    resume=True (the backlog the audit trail says is still owed: findings that arrived while the responder was
    down and incidents it was killed in the middle of; closed ones are not repeated).
    on_tick() runs every loop: the heartbeat hook.
    One worker per incident, so a person taking a minute to tap Approve does not block the next finding."""
    findings_dir = Path(findings_dir)
    from .recovery import backlog
    owed = backlog(responder, findings_dir, resume_max_age_s) if resume else []
    seen = set() if (replay or since is not None) and not resume else {p.name for p in findings_dir.glob("*.json")}

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
        for p in owed:
            pool.submit(work, p)
        while not stop.is_set():
            if on_tick:
                on_tick()
            for p in sorted(findings_dir.glob("*.json")):
                if p.name in seen:
                    continue
                if since is not None and p.stat().st_mtime < since:
                    seen.add(p.name)
                    continue
                seen.add(p.name)
                pool.submit(work, p)
            stop.wait(poll_s)
