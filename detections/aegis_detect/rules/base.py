"""Rule base class, registry and the sliding event window rules can look back into."""
from __future__ import annotations

import bisect
from datetime import timedelta
from typing import Callable, Iterable

from ..model import Detection, Event
from ..policy import Policy

REGISTRY: dict[str, "Rule"] = {}


class Window:
    """Recent events ordered by event time. Rules ask questions about the past of the current event."""

    def __init__(self, keep_seconds: int = 900):
        self.keep = timedelta(seconds=keep_seconds)
        self._events: list[Event] = []
        self._times: list[float] = []

    def add(self, ev: Event) -> None:
        ts = ev.time.timestamp()
        i = bisect.bisect_right(self._times, ts)
        self._times.insert(i, ts)
        self._events.insert(i, ev)
        cutoff = self._times[-1] - self.keep.total_seconds()
        j = bisect.bisect_left(self._times, cutoff)
        if j:
            del self._times[:j]
            del self._events[:j]

    def recent(self, ev: Event, seconds: int, where: Callable[[Event], bool] = lambda e: True) -> list[Event]:
        lo = ev.time.timestamp() - seconds
        hi = ev.time.timestamp()
        i = bisect.bisect_left(self._times, lo)
        j = bisect.bisect_right(self._times, hi)
        return [e for e in self._events[i:j] if where(e)]


class Rule:
    id = ""
    title = ""
    description = ""
    technique = ""
    tactic = ""
    severity = "medium"
    cooldown = 60                      # seconds of event time during which a repeat is suppressed
    resource_type = "Other"

    def evaluate(self, ev: Event, window: Window, policy: Policy) -> Iterable[Detection]:  # pragma: no cover
        raise NotImplementedError

    def detection(self, ev: Event, *, resource_id: str = "", severity: str | None = None,
                  title: str | None = None, dedup: str = "", technique: str | None = None,
                  evidence: Iterable[Event] = (), resource_type: str | None = None) -> Detection:
        return Detection(
            rule_id=self.id, title=title or self.title, description=self.description,
            technique=technique or self.technique, tactic=self.tactic, severity=severity or self.severity,
            account_id=ev.account_id, principal=ev.principal,
            resource_type=resource_type or self.resource_type, resource_id=resource_id or ev.account_id,
            event_time=ev.time, event_id=ev.id, event_name=ev.name,
            dedup_key=f"{self.id}|{dedup or ev.principal}", evidence=[e.id for e in evidence] or [ev.id],
            access_key_id=str((ev.raw.get("userIdentity") or {}).get("accessKeyId") or ""))


def register(cls):
    inst = cls()
    if not (inst.id and inst.technique and inst.tactic):
        raise ValueError(f"{cls.__name__} needs id, technique and tactic")
    if inst.id in REGISTRY:
        raise ValueError(f"duplicate rule id {inst.id}")
    REGISTRY[inst.id] = inst
    return cls