"""Playbook contract. plan() only READS. contain() is the only place that changes anything, and the engine calls
it only after a human approved the plan that plan() produced."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..incident import Incident
from ..policy import ResponsePolicy


class PlaybookRefusal(Exception):
    """The playbook will not act on this incident, and says why (shown to the human)."""


@dataclass
class Plan:
    summary: list[str]                        # one line per action, shown in the approval message
    facts: dict = field(default_factory=dict)  # enrichment, safe to log
    targets: dict = field(default_factory=dict)  # machine-readable input for contain() / verify()

    @property
    def actionable(self) -> bool:
        return bool(self.targets.get("actions"))


@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ""
    data: dict = field(default_factory=dict)  # safe to log: never key material


class Playbook:
    id = ""
    title = ""

    def matches(self, inc: Incident, policy: ResponsePolicy) -> bool:
        cfg = policy.playbook(self.id)
        return bool(cfg.get("enabled")) and inc.rule in cfg.get("rules", [])

    def plan(self, inc: Incident, clients, policy: ResponsePolicy) -> Plan:  # pragma: no cover
        raise NotImplementedError

    def contain(self, inc: Incident, clients, plan: Plan, policy: ResponsePolicy) -> list[Step]:  # pragma: no cover
        raise NotImplementedError

    def verify(self, inc: Incident, clients, plan: Plan) -> Step:  # pragma: no cover
        raise NotImplementedError

    def rollback(self, clients, records: list[dict]) -> list[Step]:
        return [Step("rollback", False, "no automated rollback for this playbook")]
