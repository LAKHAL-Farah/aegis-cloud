from __future__ import annotations

from dataclasses import dataclass, field

ACTIONS = ("contain_via_playbook", "escalate_to_human", "monitor")
PRIORITIES = ("P1", "P2", "P3", "P4")


@dataclass
class TriageNote:
    incident: str
    priority: str
    action: str
    playbook: str = ""
    reasons: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    summary: str = ""
    check_next: list = field(default_factory=list)
    explainer: str = "template"
    engine: str = "sequential"
    error: str = ""

    def advice_lines(self) -> list[str]:
        """What the approver sees, appended to the plan. Advisory, short, and never worded like a plan step."""
        if self.error:
            return []
        how = {"contain_via_playbook": f"the playbook `{self.playbook}` is what the plan above does; you still decide",
               "escalate_to_human": "no automatic containment applies; a person should look",
               "monitor": "no containment proposed; keep watching"}[self.action]
        by = "model" if self.explainer == "anthropic" else "template"       # the approver should know who wrote the words
        lines = [f"[triage, advisory only, words by {by}] {self.priority}: {self.summary}",
                 f"[triage] proposal: {how}",
                 "[triage] evidence: " + "; ".join(self.evidence)]
        if self.check_next:
            lines.append("[triage] check next: " + "; ".join(self.check_next))
        return [ln[:260] for ln in lines]

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("incident", "priority", "action", "playbook", "reasons", "evidence", "summary",
                                              "check_next", "explainer", "engine", "error")}
