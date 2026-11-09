"""Escalation techniques and the search for paths to admin.

Each technique is one permission pattern a person could abuse. They are written from the public descriptions of IAM
privilege escalation (the Rhino Security Labs research and the AWS documentation) as behaviour, not from any lab
account (ADR-0013 applies here too: see tests/test_not_rigged.py).

A path is a chain of BECOME edges (act as another principal) ending in a GRANT edge (give yourself more power) or in a
principal that is already admin. The search is breadth-first, so it reports a shortest path, not every path."""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from .account import Account
from .graph import ADMIN, BECOME, GRANT, Edge, Graph
from .iam_eval import evaluate, statements

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policy.json"

CATALOGUE = {
    "ESC-01": dict(name="Create a new default version of a policy you have", attack="T1098", fix="Deny iam:CreatePolicyVersion on policies attached to the caller; let only a pipeline role edit policies."),
    "ESC-02": dict(name="Switch to an older, wider version of a policy you have", attack="T1098", fix="Delete old policy versions that grant more than the current one; deny iam:SetDefaultPolicyVersion."),
    "ESC-03": dict(name="Attach an admin policy to yourself or your group or role", attack="T1098.003", fix="Remove iam:Attach*Policy from non-admin identities, or cap them with a permission boundary."),
    "ESC-04": dict(name="Write an inline admin policy on yourself or your group or role", attack="T1098.003", fix="Remove iam:Put*Policy from non-admin identities, or cap them with a permission boundary."),
    "ESC-05": dict(name="Add yourself to a group that is admin", attack="T1098.003", fix="Remove iam:AddUserToGroup, or scope it to groups that carry no admin rights."),
    "ESC-06": dict(name="Create an access key for another user", attack="T1098.001", fix="Scope iam:CreateAccessKey to the caller's own user (${aws:username})."),
    "ESC-07": dict(name="Set or reset another user's console password", attack="T1098.001", fix="Scope iam:CreateLoginProfile and iam:UpdateLoginProfile to the caller's own user."),
    "ESC-08": dict(name="Rewrite a role's trust policy so you can assume it", attack="T1098.003", fix="Remove iam:UpdateAssumeRolePolicy from everyone except a pipeline role."),
    "ESC-09": dict(name="Assume a more powerful role", attack="T1078.004", fix="Narrow the role's trust policy to named principals and add conditions (MFA, source)."),
    "ESC-10": dict(name="Pass a powerful role to a new Lambda function and invoke it", attack="T1648", fix="Scope iam:PassRole to specific roles, with iam:PassedToService; deny it for admin roles."),
    "ESC-11": dict(name="Pass a powerful role to a new EC2 instance", attack="T1578.002", fix="Scope iam:PassRole to specific roles, with iam:PassedToService; deny it for admin roles."),
    "ESC-12": dict(name="Pass a powerful role to a CloudFormation stack", attack="T1098.003", fix="Scope iam:PassRole to specific roles, with iam:PassedToService; deny it for admin roles."),
    "ESC-13": dict(name="Remove your own permission boundary", attack="T1098.003", fix="Deny iam:Delete*PermissionsBoundary and iam:Put*PermissionsBoundary for everyone the boundary applies to."),
    "ADMIN": dict(name="Already admin (Allow * on *)", attack="T1078.004", fix="Replace the wildcard with the permissions the identity actually uses (make sentinel-leastpriv)."),
}

PASS_COMBOS = (
    ("ESC-10", "lambda.amazonaws.com", ("lambda:CreateFunction", "lambda:InvokeFunction")),
    ("ESC-11", "ec2.amazonaws.com", ("ec2:RunInstances",)),
    ("ESC-12", "cloudformation.amazonaws.com", ("cloudformation:CreateStack",)),
)
KIND_ACTION = {"user": "User", "group": "Group", "role": "Role"}


def load_policy(path: str | Path | None = None) -> dict:
    data = json.loads(Path(path or DEFAULT_POLICY).read_text())
    return {k: v for k, v in data.items() if not k.startswith("_")}


def _wildcard_doc(doc) -> bool:
    return any(st.effect == "Allow" and st.matches_action("*") and "*" in st.resources for st in statements(doc))


def _capped(acct: Account, arn: str) -> bool:
    """A permission boundary that is not itself a full wildcard caps whatever the holder grants itself."""
    b = acct.boundary_statements(arn)
    return b is not None and not any(st.effect == "Allow" and st.matches_action("*") and "*" in st.resources for st in b)


def build(acct: Account) -> tuple[Graph, dict]:
    """Return the graph with every escalation edge, and `capped`: actor -> techniques a boundary neutralises."""
    g, capped = Graph(acct), {}
    actors = acct.actors()
    for a in actors:
        if acct.standing_admin(a):
            g.add(Edge(a, ADMIN, GRANT, "ADMIN", "Allow * on *", CATALOGUE["ADMIN"]["attack"]))
        _become_edges(acct, g, a, actors)
        _grant_edges(acct, g, a, capped)
    return g, capped


def _can(acct, actor, action, resource=None) -> bool:
    return acct.can(actor, action, resource).allowed


def _cond(acct, actor, action, resource=None) -> bool:
    return acct.can(actor, action, resource).conditional


def _become_edges(acct: Account, g: Graph, a: str, actors: list[str]) -> None:
    for t in actors:
        if t == a:
            continue
        kind = acct.kind(t)
        if kind == "user":
            for tid, action in (("ESC-06", "iam:CreateAccessKey"), ("ESC-07", "iam:CreateLoginProfile"), ("ESC-07", "iam:UpdateLoginProfile")):
                if _can(acct, a, action, t):
                    g.add(Edge(a, t, BECOME, tid, f"{action} on {acct.name(t)}", CATALOGUE[tid]["attack"], _cond(acct, a, action, t)))
        if kind == "role":
            how, tcond = acct.trusts(t, a)
            if how == "explicit":
                g.add(Edge(a, t, BECOME, "ESC-09", f"trust policy of {acct.name(t)} names the caller", CATALOGUE["ESC-09"]["attack"], tcond))
            elif how == "root" and _can(acct, a, "sts:AssumeRole", t):
                g.add(Edge(a, t, BECOME, "ESC-09", f"sts:AssumeRole on {acct.name(t)}", CATALOGUE["ESC-09"]["attack"],
                           tcond or _cond(acct, a, "sts:AssumeRole", t)))
            if _can(acct, a, "iam:UpdateAssumeRolePolicy", t):
                g.add(Edge(a, t, BECOME, "ESC-08", f"iam:UpdateAssumeRolePolicy on {acct.name(t)}", CATALOGUE["ESC-08"]["attack"],
                           _cond(acct, a, "iam:UpdateAssumeRolePolicy", t)))
            if _can(acct, a, "iam:PassRole", t):
                services = acct.trusted_services(t)
                for tid, svc, needs in PASS_COMBOS:
                    if svc in services and all(_can(acct, a, n, None) for n in needs):
                        g.add(Edge(a, t, BECOME, tid, f"iam:PassRole on {acct.name(t)} + {' + '.join(needs)}", CATALOGUE[tid]["attack"],
                                   _cond(acct, a, "iam:PassRole", t)))


def _grant_edges(acct: Account, g: Graph, a: str, capped: dict) -> None:
    found: list[tuple[str, str, str, bool]] = []            # (technique, label, attack, conditional)
    own = [a] + (acct.groups_of(a) if acct.kind(a) == "user" else [])
    for x in own:
        kind = KIND_ACTION[acct.kind(x)]
        for tid, verb in (("ESC-03", "Attach"), ("ESC-04", "Put")):
            action = f"iam:{verb}{kind}Policy"
            if _can(acct, a, action, x):
                found.append((tid, f"{action} on {acct.name(x)}", CATALOGUE[tid]["attack"], _cond(acct, a, action, x)))
    for pol in sorted(set(acct.attached_policy_arns(a))):
        meta = acct.policies.get(pol)
        if not meta or meta.get("aws_managed"):
            continue                                        # AWS-managed policies cannot be edited by customers
        if _can(acct, a, "iam:CreatePolicyVersion", pol):
            found.append(("ESC-01", f"iam:CreatePolicyVersion on {meta['name']}", CATALOGUE["ESC-01"]["attack"], _cond(acct, a, "iam:CreatePolicyVersion", pol)))
        if _can(acct, a, "iam:SetDefaultPolicyVersion", pol) and any(_wildcard_doc(v) for v in meta.get("other_versions", [])):
            found.append(("ESC-02", f"iam:SetDefaultPolicyVersion on {meta['name']} (an older version is Allow * on *)",
                          CATALOGUE["ESC-02"]["attack"], _cond(acct, a, "iam:SetDefaultPolicyVersion", pol)))
    if acct.kind(a) == "user":
        for grp in sorted(g_ for g_, p in acct.principals.items() if p["kind"] == "group"):
            if grp in acct.groups_of(a) or not _can(acct, a, "iam:AddUserToGroup", grp):
                continue
            if evaluate(_group_statements(acct, grp), None, "*", "*").allowed:
                found.append(("ESC-05", f"iam:AddUserToGroup on {acct.name(grp)} (admin group)", CATALOGUE["ESC-05"]["attack"],
                              _cond(acct, a, "iam:AddUserToGroup", grp)))
    if _capped(acct, a):
        capped[a] = sorted({f[0] for f in found})
        found = []
    # Removing the boundary only matters when the identity policies are what holds the power.
    b = acct.principals[a].get("boundary")
    if b and acct.kind(a) in ("user", "role"):
        action = f"iam:Delete{KIND_ACTION[acct.kind(a)]}PermissionsBoundary"
        if _can(acct, a, action, a) and evaluate(acct.identity_statements(a), None, "*", "*").allowed:
            found.append(("ESC-13", f"{action} on {acct.name(a)}, then the identity policies are Allow * on *",
                          CATALOGUE["ESC-13"]["attack"], _cond(acct, a, action, a)))
    for tid, label, attack, cond in found:
        g.add(Edge(a, ADMIN, GRANT, tid, label, attack, cond))


def _group_statements(acct: Account, grp: str):
    p = acct.principals[grp]
    out = []
    for name, doc in p["inline"].items():
        out += statements(doc, f"inline:{name}")
    for pol in p["attached"]:
        out += acct._policy_stmts(pol)
    return out


def scan(snap: dict, policy: dict | None = None, extra_denies=None) -> dict:
    policy = policy if policy is not None else load_policy()
    acct = Account(snap, extra_denies)
    graph, capped = build(acct)
    expected = policy.get("expected_admins", [])
    result, counts = {}, {"admin": 0, "expected_admin": 0, "escalates": 0, "capped": 0, "ordinary": 0}
    for a in acct.actors():
        name = acct.name(a)
        entry = {"name": name, "kind": acct.kind(a), "category": "ordinary", "hops": 0, "path": [], "capped": capped.get(a, []),
                 "boundary": bool(acct.principals[a].get("boundary"))}
        if acct.standing_admin(a):
            entry["category"] = "expected_admin" if any(fnmatch.fnmatch(name, p) for p in expected) else "admin"
        else:
            path = graph.shortest_path(a)
            if path:
                entry.update(category="escalates", hops=len(path), path=[_step(acct, e) for e in path])
            elif capped.get(a):
                entry["category"] = "capped"
        counts[entry["category"]] += 1
        result[a] = entry
    return {
        "schema": "aegis.sentinel-scan/v1", "account_id": acct.id, "collected_at": snap.get("collected_at", ""),
        "principals": result, "summary": counts,
        "unresolved": list(snap.get("unresolved", [])),
        "approximate": sorted(a for a, p in snap["policies"].items() if p.get("approximate")),
        "bundled": sorted(a for a, p in snap["policies"].items() if p.get("bundled")),
    }


def _step(acct: Account, e: Edge) -> dict:
    dst = "ADMIN" if e.dst == ADMIN else acct.name(e.dst)
    return {"from": acct.name(e.src), "to": dst, "technique": e.technique, "label": e.label, "attack": e.attack,
            "conditional": e.conditional, "kind": e.kind}
