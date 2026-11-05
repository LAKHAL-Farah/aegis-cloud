"""Checkpoint: what the detector must remember so a restart resumes instead of starting 'from now'.

Without it, every event delivered while the detector was down is skipped forever (prime() marks the whole
backlog as read). With it, the backlog is read on restart. Delivery becomes at-least-once: a crash between
emitting an alert and saving the checkpoint can emit that alert twice. The responder's ledger absorbs repeats
(ADR-0018).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

VERSION = 1


def _key(source) -> str:
    return f"{source.name}:{getattr(source, 'account_id', '')}"


class Checkpoint:
    def __init__(self, path: Path | str):
        self.path = Path(path)

    def load(self) -> dict | None:
        """None when there is nothing usable. A corrupt file is treated as absent, never as a crash."""
        try:
            data = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) and data.get("version") == VERSION else None

    def save(self, sources, engine) -> None:
        data = {"version": VERSION, "sources": {_key(s): s.state() for s in sources}, "engine": engine.state()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, self.path)

    @staticmethod
    def apply(data: dict, sources, engine) -> int:
        """Restore every source the checkpoint knows. Returns how many sources were restored."""
        restored = 0
        for s in sources:
            st = data.get("sources", {}).get(_key(s))
            if st is not None:
                s.restore(st)
                restored += 1
        engine.restore(data.get("engine", {}))
        return restored
