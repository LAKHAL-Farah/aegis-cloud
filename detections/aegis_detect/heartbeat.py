"""Liveness heartbeat. Contract: docs/ops-contract.md (the ops watchdog reads this file, nothing else)."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path


class Heartbeat:
    def __init__(self, path: Path | str, component: str, clock=time.time):
        self.path, self.component, self.clock, self.seq = Path(path), component, clock, 0

    def beat(self, **extra) -> None:
        self.seq += 1
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"component": self.component, "ts": self.clock(), "pid": os.getpid(),
                                   "seq": self.seq, **extra}))
        os.replace(tmp, self.path)
