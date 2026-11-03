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