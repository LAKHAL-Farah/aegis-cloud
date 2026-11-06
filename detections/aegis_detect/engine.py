"""The engine: events in, deduplicated detections out. No I/O here, so every rule is unit-testable."""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from typing import Callable, Iterable

from .model import Detection, Event
from .policy import Policy
from .rules import Window, all_rules


class Engine:
    def __init__(self, policy: Policy | None = None, now: Callable[[], datetime] | None = None,
                 max_seen: int = 50_000):
        self.policy = policy or Policy.load()
        self.rules = all_rules()
        self.window = Window()
        self.now = now or (lambda: datetime.now(timezone.utc))
        self._seen: "OrderedDict[str, None]" = OrderedDict()
        self._max_seen = max_seen
        self._last: dict[str, float] = {}

    def seen_ids(self) -> list[str]:
        return list(self._seen)

    def mark_seen(self, ids: Iterable[str]) -> None:
        for i in ids:
            self._seen[i] = None
        while len(self._seen) > self._max_seen:
            self._seen.popitem(last=False)

    def state(self, keep: int = 5000) -> dict:
        """What a restarted engine needs to not repeat itself: recent event ids and the cooldown clock.
        Rule windows (sliding-window correlation) are NOT saved; see ADR-0018."""
        return {"seen": list(self._seen)[-keep:], "last": dict(self._last)}

    def restore(self, state: dict) -> None:
        self.mark_seen(state.get("seen", []))
        self._last.update({k: float(v) for k, v in state.get("last", {}).items()})

    def process(self, events: Iterable[Event]) -> list[Detection]:
        out: list[Detection] = []
        for ev in sorted(events, key=lambda e: e.time):
            if ev.id in self._seen:
                continue
            self.mark_seen([ev.id])
            self.window.add(ev)
            for rule in self.rules:
                for det in rule.evaluate(ev, self.window, self.policy) or []:
                    last = self._last.get(det.dedup_key)
                    if last is not None and 0 <= ev.time.timestamp() - last < rule.cooldown:
                        continue
                    self._last[det.dedup_key] = ev.time.timestamp()
                    det.detected_at = self.now()
                    out.append(det)
        return out