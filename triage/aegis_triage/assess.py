"""Priority and proposal: plain, additive, readable code. This is where decisions are made, not in the model."""
from __future__ import annotations

from .note import ACTIONS

BASE = {"low": 1, "medium": 2, "high": 3, "critical": 4}
HIGH = {"high", "critical"}


def assess(facts: dict) -> dict:
    """Score = severity (1-4) + 1 if the same principal triggered other rules nearby + 1 if the principal is admin or
    one step from admin. P1 >= 5, P2 = 4, P3 = 3, P4 below. Every point is listed in `reasons`."""
    score, reasons = BASE.get(facts["severity"], 2), [f"severity {facts['severity']}"]
    others = sorted(set(facts["related"]))
    if len(others) >= 2:
        score += 1
        reasons.append(f"same principal also triggered {len(others)} other rules close by (possible chain)")
    exp = facts["exposure"]
    if exp.get("known") and (exp["category"] == "admin" or (exp["category"] == "escalates" and exp["hops"] <= 1)):
        score += 1
        reasons.append("the principal is admin, or one step from it, according to the IAM scan")
    evidence = [f"related findings: {len(others)}" + (f" ({', '.join(others[:4])})" if others else ""),
                "IAM exposure: " + (_exposure_text(exp) if exp.get("known") else f"unknown ({exp.get('why', 'no data')})"),
                f"playbook match: {facts['playbook'] or 'none'}"]
    return {"score": score, "priority": "P1" if score >= 5 else "P2" if score == 4 else "P3" if score == 3 else "P4",
            "reasons": reasons, "evidence": evidence}


def _exposure_text(exp: dict) -> str:
    return {"admin": "admin", "expected_admin": "expected admin", "capped": "capped by a boundary", "ordinary": "ordinary",
            "escalates": f"can reach admin in {exp.get('hops', '?')} step(s)"}.get(exp["category"], exp["category"])


def propose(facts: dict, assessment: dict) -> dict:
    """One of ACTIONS. It only ever points at a playbook that already exists and that the responder policy enables."""
    if facts["protected"]:
        return {"action": "escalate_to_human", "playbook": "", "why": "protected identity: the responder will not touch it"}
    if facts["playbook"]:
        return {"action": "contain_via_playbook", "playbook": facts["playbook"], "why": "an enabled playbook matches this rule"}
    if facts["severity"] in HIGH or assessment["priority"] in ("P1", "P2"):
        return {"action": "escalate_to_human", "playbook": "", "why": "no playbook covers this rule and it is serious"}
    return {"action": "monitor", "playbook": "", "why": "no playbook and not serious"}


assert set(ACTIONS) == {"contain_via_playbook", "escalate_to_human", "monitor"}
