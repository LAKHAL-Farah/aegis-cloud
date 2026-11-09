from aegis_sentinel.escalation import scan
from twins import ACCT, collect_twin


def by_name(result):
    return {p["name"]: p for p in result["principals"].values()}


def test_purple_twin_has_one_escalation_and_one_standing_admin():
    r = by_name(scan(collect_twin(hardened=False)))
    assert r["dev-svc"]["category"] == "admin"
    assert r["intern"]["category"] == "escalates" and r["intern"]["hops"] == 1
    step = r["intern"]["path"][0]
    assert step["technique"] == "ESC-01" and step["to"] == "ADMIN" and "intern-policy" in step["label"]
    assert {n for n, p in r.items() if p["category"] in ("admin", "escalates")} == {"dev-svc", "intern"}


def test_hardened_twin_has_no_escalation_and_no_unexpected_admin():
    result = scan(collect_twin(hardened=True))
    r = by_name(result)
    assert r["dev-svc"]["category"] != "admin" and r["intern"]["category"] != "escalates"
    assert result["summary"]["admin"] == 0 and result["summary"]["escalates"] == 0
    assert r["aegis-break-glass-admin"]["category"] == "expected_admin"      # intended, so listed but not a finding


def test_boundary_is_an_allow_list_so_the_wildcard_is_cut_down():
    from aegis_sentinel.account import Account
    acct = Account(collect_twin(hardened=True))
    dev = next(a for a in acct.actors() if acct.name(a) == "dev-svc")
    assert acct.can(dev, "s3:GetObject", "*").allowed                       # inside the ceiling
    assert not acct.can(dev, "iam:AttachUserPolicy", dev).allowed           # identity allows it, the ceiling does not
    assert acct.can(dev, "iam:AttachUserPolicy", dev).boundary_blocked
    assert not acct.can(dev, "iam:CreateAccessKey", dev).allowed            # explicitly denied by the boundary


def test_collector_reads_the_real_iam_shape():
    snap = collect_twin(hardened=True)
    assert snap["account_id"] == ACCT and snap["unresolved"] == []
    kinds = {p["name"]: p["kind"] for p in snap["principals"].values()}
    assert kinds["intern"] == "user" and kinds["aegis-deployer"] == "role"
    admin = snap["policies"]["arn:aws:iam::aws:policy/AdministratorAccess"]
    assert admin["aws_managed"] and admin["doc"]["Statement"]


def test_a_listing_that_omits_the_boundary_is_double_checked():
    """Real emulators drop fields. A missing boundary would overstate risk, so the collector asks get_user directly."""
    from aegis_sentinel import snapshot
    arn = f"arn:aws:iam::{ACCT}:policy/b"

    class Iam:
        def get_paginator(self, _):
            class P:
                def paginate(self, **kw):
                    return [{"UserDetailList": [{"UserName": "u", "Arn": f"arn:aws:iam::{ACCT}:user/u", "UserPolicyList": [],
                                                 "GroupList": [], "AttachedManagedPolicies": []}]}]
            return P()

        def get_user(self, UserName):
            return {"User": {"PermissionsBoundary": {"PermissionsBoundaryArn": arn}}}

        def get_policy(self, PolicyArn):
            raise RuntimeError("not implemented here")

    snap = snapshot.collect(Iam(), ACCT)
    assert snap["principals"][f"arn:aws:iam::{ACCT}:user/u"]["boundary"] == arn
    assert arn in snap["unresolved"]                      # a boundary that cannot be read is reported, not assumed empty


def test_aws_managed_policies_are_read_through_the_api_when_it_answers():
    from aegis_sentinel import snapshot
    managed = "arn:aws:iam::aws:policy/SomethingManaged"
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}

    class Iam:
        def get_paginator(self, _):
            class P:
                def paginate(self, **kw):
                    return [{"RoleDetailList": [{"RoleName": "r", "Arn": f"arn:aws:iam::{ACCT}:role/r", "AssumeRolePolicyDocument": {},
                                                 "AttachedManagedPolicies": [{"PolicyArn": managed}]}]}]
            return P()

        def get_role(self, RoleName):
            return {"Role": {}}

        def get_policy(self, PolicyArn):
            return {"Policy": {"PolicyName": "SomethingManaged", "DefaultVersionId": "v1"}}

        def get_policy_version(self, PolicyArn, VersionId):
            return {"PolicyVersion": {"Document": doc}}

    snap = snapshot.collect(Iam(), ACCT)
    assert snap["policies"][managed]["doc"] == doc and snap["policies"][managed]["aws_managed"] and not snap["unresolved"]
