"""An Account wraps a snapshot and answers: what is this principal allowed to do?"""
from __future__ import annotations

from functools import lru_cache

from .iam_eval import Statement, Verdict, as_list, evaluate, glob, statements
from .snapshot import BUNDLED


class Account:
    def __init__(self, snap: dict, extra_denies: list[Statement] | None = None):
        self.snap = snap
        self.id = snap["account_id"]
        self.principals = snap["principals"]
        self.policies = snap["policies"]
        self.extra_denies = extra_denies or []
        self._can = lru_cache(maxsize=None)(self._can_uncached)

    # ---- structure
    def kind(self, arn: str) -> str:
        return self.principals[arn]["kind"]

    def name(self, arn: str) -> str:
        return self.principals[arn]["name"]

    def actors(self) -> list[str]:
        return sorted(a for a, p in self.principals.items() if p["kind"] in ("user", "role"))

    def groups_of(self, arn: str) -> list[str]:
        return list(self.principals[arn].get("groups", []))

    def members_of(self, group_arn: str) -> list[str]:
        return sorted(a for a, p in self.principals.items() if group_arn in p.get("groups", []))

    def _policy_stmts(self, arn: str) -> list[Statement]:
        pol = self.policies.get(arn)
        if pol is None and arn in BUNDLED:
            pol = {"name": BUNDLED[arn]["name"], "doc": BUNDLED[arn]["doc"]}
        return statements(pol["doc"], pol["name"]) if pol else []

    def attached_policy_arns(self, arn: str, with_groups: bool = True) -> list[str]:
        p = self.principals[arn]
        out = list(p["attached"])
        if with_groups:
            for g in p.get("groups", []):
                out += self.principals[g]["attached"]
        return out

    def identity_statements(self, arn: str) -> list[Statement]:
        p = self.principals[arn]
        out: list[Statement] = []
        for name, doc in p["inline"].items():
            out += statements(doc, f"inline:{name}")
        for pol in p["attached"]:
            out += self._policy_stmts(pol)
        for g in p.get("groups", []):
            gp = self.principals[g]
            for name, doc in gp["inline"].items():
                out += statements(doc, f"group:{gp['name']}/inline:{name}")
            for pol in gp["attached"]:
                out += self._policy_stmts(pol)
        return out

    def boundary_statements(self, arn: str) -> list[Statement] | None:
        b = self.principals[arn].get("boundary")
        if not b:
            return None
        return self._policy_stmts(b)       # an unresolved boundary becomes "allows nothing": the safe reading for a ceiling

    # ---- questions
    def _can_uncached(self, arn: str, action: str, resource: str | None) -> Verdict:
        return evaluate(self.identity_statements(arn), self.boundary_statements(arn), action, resource, self.extra_denies)

    def can(self, arn: str, action: str, resource: str | None = None) -> Verdict:
        return self._can(arn, action, resource)

    def standing_admin(self, arn: str) -> bool:
        v = self.can(arn, "*", "*")
        return v.allowed and not v.conditional

    # ---- trust
    def trusts(self, role_arn: str, actor_arn: str) -> tuple[str, bool]:
        """How does the role's trust policy admit this actor? ("explicit" | "root" | "", conditional).
        "explicit" names the actor (or `*`): no permission of the actor's own is needed. "root" trusts the account,
        which only delegates: the actor's own policy must also allow sts:AssumeRole. Same account only."""
        trust = self.principals[role_arn].get("trust") or {}
        explicit, root = [], []
        for raw in as_list(trust.get("Statement")):
            if not isinstance(raw, dict) or raw.get("Effect") != "Allow":
                continue
            if not any(glob(a, "sts:AssumeRole") for a in as_list(raw.get("Action"))):
                continue
            p = raw.get("Principal")
            aws = ["*"] if p == "*" else [str(x) for x in as_list(p.get("AWS"))] if isinstance(p, dict) else []
            cond = bool(raw.get("Condition"))
            if any(x in ("*", actor_arn) for x in aws):
                explicit.append(cond)
            elif f"arn:aws:iam::{self.id}:root" in aws:
                root.append(cond)
        if explicit:
            return "explicit", all(explicit)
        if root:
            return "root", all(root)
        return "", False

    def trusted_services(self, role_arn: str) -> set[str]:
        trust = self.principals[role_arn].get("trust") or {}
        out: set[str] = set()
        for raw in as_list(trust.get("Statement")):
            if isinstance(raw, dict) and raw.get("Effect") == "Allow" and isinstance(raw.get("Principal"), dict):
                out |= {str(x) for x in as_list(raw["Principal"].get("Service"))}
        return out
