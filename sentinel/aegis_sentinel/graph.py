"""The graph: nodes are principals, edges say who can become whom or grant themselves more.

Structural edges (MEMBER_OF, HAS_POLICY, BOUNDED_BY, TRUSTS) describe IAM as configured and exist for the Cypher export.
Escalation edges (BECOME, GRANT) are what the search walks. ADMIN is a virtual node meaning "can do anything"."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .account import Account

ADMIN = "aws:admin"
BECOME, GRANT = "BECOME", "GRANT"
STRUCTURAL = ("MEMBER_OF", "HAS_POLICY", "BOUNDED_BY", "TRUSTS")


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str
    technique: str = ""        # catalogue id, e.g. ESC-01
    label: str = ""            # human readable: the permission and the resource
    attack: str = ""
    conditional: bool = False


@dataclass
class Graph:
    account: Account
    edges: list[Edge] = field(default_factory=list)

    def add(self, e: Edge) -> None:
        if e not in self.edges:
            self.edges.append(e)

    def out(self, node: str, kinds=(BECOME, GRANT)) -> list[Edge]:
        return [e for e in self.edges if e.src == node and e.kind in kinds]

    def shortest_path(self, start: str, goal: str = ADMIN) -> list[Edge] | None:
        """Breadth-first over escalation edges. Returns the edges of a shortest path, [] if start is the goal, None if unreachable."""
        if start == goal:
            return []
        seen, queue = {start}, deque([(start, [])])
        while queue:
            node, path = queue.popleft()
            for e in sorted(self.out(node), key=lambda x: (x.conditional, x.dst, x.technique)):
                if e.dst in seen:
                    continue
                if e.dst == goal:
                    return path + [e]
                seen.add(e.dst)
                queue.append((e.dst, path + [e]))
        return None


def structural_edges(acct: Account) -> list[Edge]:
    out = []
    for arn, p in acct.principals.items():
        for g in p.get("groups", []):
            out.append(Edge(arn, g, "MEMBER_OF"))
        for pol in acct.attached_policy_arns(arn, with_groups=False):
            out.append(Edge(arn, pol, "HAS_POLICY"))
        if p.get("boundary"):
            out.append(Edge(arn, p["boundary"], "BOUNDED_BY"))
        if p["kind"] == "role":
            for other in acct.actors():
                how, cond = acct.trusts(arn, other)
                if how == "explicit":
                    out.append(Edge(arn, other, "TRUSTS", conditional=cond))
    return out
