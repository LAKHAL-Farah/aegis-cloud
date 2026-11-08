"""Observed CloudTrail usage -> a least-privilege policy, checked three ways before anyone is asked to trust it.

1. coverage: every successful observed call is still allowed by the new policy (the evaluator runs over it).
2. reduction: how many actions the principal is granted now, against how many the new policy allows.
3. paths: the escalation search runs again with the old identity policies replaced; the path should be gone.

It writes a policy, never applies one. A person reviews it; `observed but sensitive` calls are listed and excluded."""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field

from .account import Account
from .actions import S3_OBJECT, SENSITIVE, Universe, to_action
from .escalation import scan
from .iam_eval import evaluate, glob, statements

SID_PREFIX = "Observed"
MAX_MANAGED_POLICY_CHARS = 6144


@dataclass
class Usage:
    arn: str
    name: str
    actions: dict = field(default_factory=dict)       # action -> set of resources seen
    no_permission: set = field(default_factory=set)
    unverified: set = field(default_factory=set)
    denied: int = 0
    events: int = 0
    first: str = ""
    last: str = ""


def _principal(ident: dict, snap: dict | None) -> tuple[str, str] | None:
    """(arn, name) of an IAM user or role, or None for root, services and anything identity policies cannot restrict."""
    kind, acct = ident.get("type", ""), str(ident.get("accountId") or (snap or {}).get("account_id") or "")
    if kind == "IAMUser":
        arn = ident.get("arn") or ""
        return (arn, arn.rsplit("/", 1)[-1]) if arn else None
    if kind == "AssumedRole":
        parts = (ident.get("arn") or "").split(":assumed-role/")[-1].split("/")
        if len(parts) < 2:
            return None
        role = parts[0]
        if snap:
            hit = next((a for a, p in snap["principals"].items() if p["kind"] == "role" and p["name"] == role), None)
            if hit:
                return hit, role
        return f"arn:aws:iam::{acct}:role/{role}", role
    return None


def usage_from_cloudtrail(records: list[dict], snap: dict | None = None) -> dict[str, Usage]:
    out: dict[str, Usage] = {}
    for rec in records:
        who = _principal(rec.get("userIdentity") or {}, snap)
        if not who:
            continue
        u = out.setdefault(who[0], Usage(who[0], who[1]))
        u.events += 1
        when = str(rec.get("eventTime", ""))
        u.first, u.last = min(u.first or when, when), max(u.last, when)
        if rec.get("errorCode"):
            u.denied += 1                      # an attempt that failed is not evidence the permission is needed
            continue
        action, how = to_action(str(rec.get("eventSource", "")), str(rec.get("eventName", "")))
        if action is None:
            u.no_permission.add(f"{rec.get('eventSource', '').removesuffix('.amazonaws.com')}:{rec.get('eventName')}")
            continue
        if how == "unverified":
            u.unverified.add(action)
        u.actions.setdefault(action, set()).update(_resources(action, rec))
    return out


def _resources(action: str, rec: dict) -> set[str]:
    rp = rec.get("requestParameters") or {}
    acct = str((rec.get("userIdentity") or {}).get("accountId") or rec.get("recipientAccountId") or "")
    region = str(rec.get("awsRegion") or "us-east-1")
    svc = action.split(":")[0]
    if svc == "s3" and rp.get("bucketName"):
        b = rp["bucketName"]
        return {f"arn:aws:s3:::{b}/*" if action in S3_OBJECT else f"arn:aws:s3:::{b}"}
    if svc == "iam":
        for key, kind in (("userName", "user"), ("roleName", "role"), ("groupName", "group")):
            if rp.get(key):
                return {f"arn:aws:iam::{acct}:{kind}/{rp[key]}"}
        if str(rp.get("policyArn", "")).startswith("arn:"):
            return {rp["policyArn"]}
    if svc == "kms" and str(rp.get("keyId", "")).startswith("arn:"):
        return {rp["keyId"]}
    if svc == "secretsmanager" and rp.get("secretId"):
        sid = str(rp["secretId"])
        return {sid if sid.startswith("arn:") else f"arn:aws:secretsmanager:{region}:{acct}:secret:{sid}-??????"}
    return {"*"}


def is_sensitive(action: str) -> bool:
    return any(glob(p, action) for p in SENSITIVE)


def generate(usage: Usage, keep_sensitive: bool = False) -> tuple[dict, dict]:
    """(policy document, notes). Statements group actions that share the same resources, in a stable order."""
    kept, held_back = {}, {}
    for action, res in usage.actions.items():
        (held_back if is_sensitive(action) and not keep_sensitive else kept)[action] = res
    groups: dict[tuple, list] = {}
    for action, res in sorted(kept.items()):
        groups.setdefault(tuple(sorted(res)) or ("*",), []).append(action)
    stmts = []
    for i, (res, acts) in enumerate(sorted(groups.items(), key=lambda kv: (kv[1][0], kv[0])), 1):
        svc = "".join(w.title() for w in acts[0].split(":")[0].split("-"))
        stmts.append({"Sid": f"{SID_PREFIX}{svc}{i}", "Effect": "Allow", "Action": sorted(acts),
                      "Resource": list(res) if len(res) > 1 else res[0]})
    doc = {"Version": "2012-10-17", "Statement": stmts}
    size = len(json.dumps(doc, separators=(",", ":")))
    return doc, {
        "actions": len(kept), "statements": len(stmts), "policy_chars": size, "fits_managed_policy": size <= MAX_MANAGED_POLICY_CHARS,
        "unscoped_actions": sorted(a for a, r in kept.items() if r == {"*"} and a != "s3:ListAllMyBuckets"),
        "sensitive_left_out": sorted(held_back), "unverified_mapping": sorted(a for a in usage.unverified if a in kept),
        "no_permission_needed": sorted(usage.no_permission), "failed_attempts": usage.denied,
    }


def granted_actions(acct: Account, arn: str, universe: Universe) -> set[str]:
    """Actions the principal is allowed today, counted against the universe (wildcards expanded, denies and the
    boundary applied). Conditions are ignored, so a conditional grant counts as granted."""
    everything = universe.everything()

    def allowed_by(stmts, effect):
        out = set()
        for st in stmts:
            if st.effect != effect or (effect == "Deny" and st.conditional):
                continue
            out |= {a for a in everything if st.matches_action(a)}
        return out

    ident = acct.identity_statements(arn)
    allowed = allowed_by(ident, "Allow") - allowed_by(ident, "Deny")
    b = acct.boundary_statements(arn)
    if b is not None:
        allowed = (allowed & allowed_by(b, "Allow")) - allowed_by(b, "Deny")
    return allowed - allowed_by(acct.extra_denies, "Deny")


def replace_identity_policies(snap: dict, arn: str, doc: dict, name: str = "aegis-least-privilege") -> dict:
    """A copy of the snapshot where the principal's own policies are only the new one. Group policies stay: if a
    group still grants admin, the principal still escalates and the report says so."""
    out = copy.deepcopy(snap)
    p = out["principals"][arn]
    p["inline"], p["attached"] = {name: doc}, []
    return out


def analyse(snap: dict, usage: Usage, universe: Universe, policy: dict | None = None, keep_sensitive: bool = False,
            extra_denies=None) -> dict:
    acct = Account(snap, extra_denies)
    doc, notes = generate(usage, keep_sensitive)
    before = granted_actions(acct, usage.arn, universe)
    after_snap = replace_identity_policies(snap, usage.arn, doc)
    after_acct = Account(after_snap, extra_denies)
    after = granted_actions(after_acct, usage.arn, universe)

    stmts = statements(doc, "generated")
    missing = []
    for action, res in sorted(usage.actions.items()):
        if action in notes["sensitive_left_out"]:
            continue
        for r in sorted(res):
            if not evaluate(stmts, None, action, r).allowed:
                missing.append(f"{action} on {r}")
    covered = sum(len(r) for a, r in usage.actions.items() if a not in notes["sensitive_left_out"])
    path_before = _category(scan(snap, policy, extra_denies), usage.arn)
    path_after = _category(scan(after_snap, policy, extra_denies), usage.arn)
    return {
        "principal": usage.name, "arn": usage.arn, "observed_events": usage.events, "window": [usage.first, usage.last],
        "granted_before": len(before), "granted_after": len(after),
        "reduction_pct": round(100 * (1 - len(after) / len(before)), 2) if before else 0.0,
        "coverage": {"checked": covered, "missing": missing, "complete": not missing},
        "category_before": path_before["category"], "category_after": path_after["category"],
        "paths_before": path_before["path"], "paths_after": path_after["path"],
        "policy": doc, "notes": notes,
    }


def _category(result: dict, arn: str) -> dict:
    return result["principals"].get(arn) or {"category": "unknown", "path": []}
