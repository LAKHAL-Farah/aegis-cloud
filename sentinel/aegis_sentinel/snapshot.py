"""A snapshot is the part of IAM the analysis needs, as plain JSON (schema aegis.iam-snapshot/v1).

`collect()` reads it from a live account (LocalStack or AWS) with read-only IAM calls. Everything else in the package
works from a snapshot, so analysis is reproducible, diff-able and testable without an account.

Principals are keyed by ARN. AWS-managed policies that the account API did not return are filled from a small bundled
table (approximate, flagged `bundled`) or listed in `unresolved`: an unresolved policy is a hole in the analysis and the
report says so instead of assuming it is harmless."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

SCHEMA = "aegis.iam-snapshot/v1"

# Policies every account has. Bundled so an offline analysis does not silently treat them as empty. The
# read-only one is an approximation of a very long list and is flagged as such.
BUNDLED = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "name": "AdministratorAccess", "approximate": False,
        "doc": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
    "arn:aws:iam::aws:policy/PowerUserAccess": {
        "name": "PowerUserAccess", "approximate": False,
        "doc": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "NotAction": ["iam:*", "organizations:*", "account:*"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["iam:CreateServiceLinkedRole", "iam:DeleteServiceLinkedRole", "iam:ListRoles",
                                           "organizations:DescribeOrganization", "account:ListRegions"], "Resource": "*"}]}},
    "arn:aws:iam::aws:policy/IAMFullAccess": {
        "name": "IAMFullAccess", "approximate": False,
        "doc": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}},
    "arn:aws:iam::aws:policy/ReadOnlyAccess": {
        "name": "ReadOnlyAccess", "approximate": True,
        "doc": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["*:Get*", "*:List*", "*:Describe*"],
                                                         "Resource": "*"}]}},
}


def _doc(value):
    """boto3 returns policy documents decoded; some emulators return a JSON string or a URL-encoded one."""
    if isinstance(value, str):
        text = unquote(value) if value.startswith("%7B") else value
        return json.loads(text)
    return value or {}


def _arns(detail: dict) -> list[str]:
    return [p["PolicyArn"] for p in detail.get("AttachedManagedPolicies", []) if p.get("PolicyArn")]


def empty(account_id: str) -> dict:
    return {"schema": SCHEMA, "account_id": account_id, "collected_at": _now(), "principals": {}, "policies": {}, "unresolved": []}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path: str | Path) -> dict:
    snap = json.loads(Path(path).read_text())
    if snap.get("schema") != SCHEMA:
        raise ValueError(f"{path}: not an {SCHEMA} snapshot")
    return snap


def save(snap: dict, path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snap, indent=2, sort_keys=True))


def collect(iam, account_id: str) -> dict:
    """Read users, groups, roles and customer-managed policies. Only Get*/List* calls."""
    snap = empty(account_id)
    group_arn = {}
    pages = list(iam.get_paginator("get_account_authorization_details").paginate(
        Filter=["User", "Role", "Group", "LocalManagedPolicy"]))
    for page in pages:
        for g in page.get("GroupDetailList", []):
            group_arn[g["GroupName"]] = g["Arn"]
    for page in pages:
        for g in page.get("GroupDetailList", []):
            snap["principals"][g["Arn"]] = {
                "kind": "group", "name": g["GroupName"], "boundary": None, "trust": None, "groups": [],
                "inline": {p["PolicyName"]: _doc(p["PolicyDocument"]) for p in g.get("GroupPolicyList", [])},
                "attached": _arns(g)}
        for u in page.get("UserDetailList", []):
            snap["principals"][u["Arn"]] = {
                "kind": "user", "name": u["UserName"], "trust": None,
                "boundary": (u.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                "groups": [group_arn[n] for n in u.get("GroupList", []) if n in group_arn],
                "inline": {p["PolicyName"]: _doc(p["PolicyDocument"]) for p in u.get("UserPolicyList", [])},
                "attached": _arns(u)}
        for r in page.get("RoleDetailList", []):
            snap["principals"][r["Arn"]] = {
                "kind": "role", "name": r["RoleName"], "groups": [],
                "boundary": (r.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn"),
                "trust": _doc(r.get("AssumeRolePolicyDocument")),
                "inline": {p["PolicyName"]: _doc(p["PolicyDocument"]) for p in r.get("RolePolicyList", [])},
                "attached": _arns(r)}
        for p in page.get("Policies", []):
            versions = p.get("PolicyVersionList", [])
            default = next((v for v in versions if v.get("IsDefaultVersion")), None)
            snap["policies"][p["Arn"]] = {
                "name": p.get("PolicyName") or p["Arn"].rsplit("/", 1)[-1],      # moto omits PolicyName
                "aws_managed": False, "bundled": False,
                "doc": _doc(default["Document"]) if default else {},
                "other_versions": [_doc(v["Document"]) for v in versions if not v.get("IsDefaultVersion")]}
    _confirm_boundaries(iam, snap)
    _resolve_missing(iam, snap)
    return snap


def _confirm_boundaries(iam, snap: dict) -> None:
    """A permission boundary is a ceiling. If a listing silently omits it the analysis would overstate what the
    principal can do, so every principal that shows no boundary is asked directly (get_user / get_role)."""
    for arn, p in snap["principals"].items():
        if p["boundary"] or p["kind"] not in ("user", "role"):
            continue
        try:
            got = (iam.get_user(UserName=p["name"])["User"] if p["kind"] == "user"
                   else iam.get_role(RoleName=p["name"])["Role"])
            p["boundary"] = (got.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        except Exception:  # noqa: BLE001 - an unreadable principal keeps what the listing said
            snap.setdefault("warnings", []).append(f"could not confirm the permission boundary of {p['name']}")


def _resolve_missing(iam, snap: dict) -> None:
    wanted = {a for p in snap["principals"].values() for a in p["attached"]} | {
        p["boundary"] for p in snap["principals"].values() if p["boundary"]}
    for arn in sorted(wanted - set(snap["policies"])):
        try:
            meta = iam.get_policy(PolicyArn=arn)["Policy"]
            ver = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])["PolicyVersion"]
            snap["policies"][arn] = {"name": meta["PolicyName"], "aws_managed": arn.startswith("arn:aws:iam::aws:"),
                                     "bundled": False, "doc": _doc(ver["Document"]), "other_versions": []}
            continue
        except Exception:  # noqa: BLE001 - an emulator may not implement it; fall through to the table
            pass
        if arn in BUNDLED:
            b = BUNDLED[arn]
            snap["policies"][arn] = {"name": b["name"], "aws_managed": True, "bundled": True,
                                     "approximate": b["approximate"], "doc": b["doc"], "other_versions": []}
        else:
            snap["unresolved"].append(arn)
