"""A small IAM evaluator: identity policies, a permission boundary and extra account-wide denies (SCP-style).

What it models
* Allow / Deny statements with Action, NotAction, Resource, NotResource and `*` / `?` wildcards.
* An explicit Deny always wins. The permission boundary is an allow list: an action must be allowed by the
  identity policies AND by the boundary.
* Conditions are NOT evaluated. A statement with a Condition is treated as "might apply": a conditional Allow gives a
  `conditional` verdict, a conditional Deny does not remove an Allow. The report says which results are conditional.

What it does not model (docs/localstack-limitations.md, ADR-0019): session policies, resource-based policies,
service control policies other than the plain denies it is given, and cross-account access.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache


def as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


@lru_cache(maxsize=4096)
def _rx(pattern: str) -> re.Pattern:
    out = []
    for ch in pattern:
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def glob(pattern: str, value: str) -> bool:
    """IAM wildcard match (`*`, `?`), case-insensitive, as IAM does for action names."""
    return bool(_rx(str(pattern)).match(str(value)))


@dataclass(frozen=True)
class Statement:
    effect: str
    actions: tuple = ()
    not_actions: tuple = ()
    resources: tuple = ()
    not_resources: tuple = ()
    conditional: bool = False
    source: str = ""            # which policy it came from, for explanations

    def matches_action(self, action: str) -> bool:
        if action == "*":        # the question "is this a full wildcard grant?"
            return any(a in ("*", "*:*") for a in self.actions)
        if self.actions:
            return any(glob(a, action) for a in self.actions)
        if self.not_actions:
            return not any(glob(a, action) for a in self.not_actions)
        return False

    def matches_resource(self, resource: str | None) -> bool:
        """`None` means "on any resource": true when the statement names or excludes anything at all."""
        if resource is None:
            return True
        if self.resources:
            return any(glob(r, resource) for r in self.resources)
        if self.not_resources:
            return not any(glob(r, resource) for r in self.not_resources)
        return False


def statements(doc, source: str = "") -> list[Statement]:
    if isinstance(doc, str):
        import json
        doc = json.loads(doc)
    if not isinstance(doc, dict):
        return []
    out = []
    for st in as_list(doc.get("Statement")):
        if not isinstance(st, dict):
            continue
        out.append(Statement(
            effect=str(st.get("Effect", "")), actions=tuple(map(str, as_list(st.get("Action")))),
            not_actions=tuple(map(str, as_list(st.get("NotAction")))),
            resources=tuple(map(str, as_list(st.get("Resource")))),
            not_resources=tuple(map(str, as_list(st.get("NotResource")))),
            conditional=bool(st.get("Condition")), source=source or str(st.get("Sid", "")),
        ))
    return out


@dataclass
class Verdict:
    allowed: bool = False
    conditional: bool = False        # allowed only if a Condition holds (not evaluated)
    denied_by: str = ""
    via: list = field(default_factory=list)      # policies that grant it
    boundary_blocked: bool = False


def evaluate(identity: list[Statement], boundary: list[Statement] | None, action: str, resource: str | None = None,
             extra_denies: list[Statement] | None = None) -> Verdict:
    """Is `action` on `resource` allowed? `boundary=None` means no permission boundary is attached."""
    for st in [*identity, *(boundary or []), *(extra_denies or [])]:
        if st.effect == "Deny" and not st.conditional and st.matches_action(action) and st.matches_resource(resource):
            return Verdict(denied_by=st.source or "Deny")
    grants = [st for st in identity if st.effect == "Allow" and st.matches_action(action) and st.matches_resource(resource)]
    if not grants:
        return Verdict()
    if boundary is not None:
        ceiling = [st for st in boundary if st.effect == "Allow" and st.matches_action(action) and st.matches_resource(resource)]
        if not ceiling:
            return Verdict(boundary_blocked=True, via=sorted({g.source for g in grants}))
        cond = all(g.conditional for g in grants) or all(c.conditional for c in ceiling)
    else:
        cond = all(g.conditional for g in grants)
    return Verdict(allowed=True, conditional=cond, via=sorted({g.source for g in grants}))
