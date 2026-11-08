import pytest
from aegis_sentinel import leastpriv
from aegis_sentinel.actions import Universe
from twins import ACCT, collect_twin


class Small(Universe):
    """A fixed universe so the arithmetic in these tests is checkable by hand."""
    DATA = {"s3": ["GetObject", "PutObject", "ListAllMyBuckets", "ListBucket", "DeleteObject"],
            "iam": ["CreateAccessKey", "CreatePolicyVersion", "SetDefaultPolicyVersion", "ListPolicyVersions", "GetUser"],
            "sts": ["GetCallerIdentity", "AssumeRole"], "cloudtrail": ["StopLogging", "LookupEvents"]}

    def prefixes(self):
        return sorted(self.DATA)

    def actions(self, prefix):
        return frozenset(f"{prefix}:{o}" for o in self.DATA.get(prefix, []))


def rec(name, source, who="dev-svc", err="", **req):  # noqa: E501
    arn = f"arn:aws:iam::{ACCT}:user/{who}"
    r = {"eventTime": "2026-11-05T10:00:00Z", "eventSource": f"{source}.amazonaws.com", "eventName": name, "awsRegion": "us-east-1",
         "requestParameters": req or None, "recipientAccountId": ACCT,
         "userIdentity": {"type": "IAMUser", "arn": arn, "accountId": ACCT, "userName": who}}
    if err:
        r["errorCode"] = err
    return r


RUN = [rec("ListBuckets", "s3"), rec("GetObject", "s3", bucketName="data"), rec("GetObject", "s3", bucketName="data"),
       rec("PutObject", "s3", bucketName="data"), rec("GetCallerIdentity", "sts"),
       rec("CreateAccessKey", "iam", userName="backdoor"), rec("StopLogging", "cloudtrail", trailName="trail"),
       rec("DeleteObject", "s3", err="AccessDenied", bucketName="data")]


def usage(who="dev-svc"):
    snap = collect_twin(hardened=False)
    return snap, leastpriv.usage_from_cloudtrail(RUN, snap)[f"arn:aws:iam::{ACCT}:user/{who}"]


def test_failed_attempts_and_no_permission_calls_are_not_turned_into_permissions():
    _, u = usage()
    assert "s3:DeleteObject" not in u.actions and u.denied == 1
    assert "sts:GetCallerIdentity" not in u.actions and "sts:GetCallerIdentity" in u.no_permission


def test_attack_calls_are_reported_but_left_out_of_the_policy():
    _, u = usage()
    doc, notes = leastpriv.generate(u)
    allowed = {a for s in doc["Statement"] for a in s["Action"]}
    assert "iam:CreateAccessKey" not in allowed and "cloudtrail:StopLogging" not in allowed
    assert set(notes["sensitive_left_out"]) == {"iam:CreateAccessKey", "cloudtrail:StopLogging"}
    kept, _ = leastpriv.generate(u, keep_sensitive=True)
    assert "iam:CreateAccessKey" in {a for s in kept["Statement"] for a in s["Action"]}


def test_policy_is_scoped_to_the_resources_that_were_seen_and_is_stable():
    _, u = usage()
    doc, _ = leastpriv.generate(u)
    by_action = {a: s["Resource"] for s in doc["Statement"] for a in s["Action"]}
    assert by_action["s3:GetObject"] == "arn:aws:s3:::data/*" and by_action["s3:ListAllMyBuckets"] == "*"
    assert leastpriv.generate(u)[0] == doc


def test_wildcard_user_loses_nearly_everything_and_coverage_is_complete():
    snap, u = usage()
    r = leastpriv.analyse(snap, u, Small())
    assert r["granted_before"] == len(Small().everything()) and r["granted_after"] == 3
    assert r["reduction_pct"] == 78.57 and r["coverage"]["complete"]      # 3 of 14 actions remain
    assert r["category_before"] == "admin" and r["category_after"] == "ordinary"


def test_escalating_user_is_fixed_by_the_swap():
    snap = collect_twin(hardened=False)
    records = [rec("ListBuckets", "s3", who="intern")]
    u = leastpriv.usage_from_cloudtrail(records, snap)[f"arn:aws:iam::{ACCT}:user/intern"]
    r = leastpriv.analyse(snap, u, Small())
    assert r["category_before"] == "escalates" and r["category_after"] == "ordinary"
    assert r["granted_before"] == 4 and r["granted_after"] == 1 and r["reduction_pct"] == 75.0


def test_a_group_that_still_grants_admin_keeps_the_path_and_the_report_says_so():
    from support import allow, arn, doc, snap as build
    s = build(users=[("u", {"groups": ["admins"]})], groups=[("admins", {"inline": {"p": doc(allow("*"))}})])
    u = leastpriv.Usage(arn("user", "u"), "u", {"s3:ListAllMyBuckets": {"*"}}, events=1)
    r = leastpriv.analyse(s, u, Small(), {"expected_admins": []})
    assert r["category_after"] == "admin"


def test_assumed_role_events_are_attributed_to_the_role():
    snap = collect_twin(hardened=True)
    r = {"eventTime": "t", "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets",
         "userIdentity": {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCT}:assumed-role/aegis-deployer/session1", "accountId": ACCT}}
    got = leastpriv.usage_from_cloudtrail([r], snap)
    assert list(got) == [f"arn:aws:iam::{ACCT}:role/aegis-deployer"]


def test_root_and_service_events_are_ignored():
    r = {"eventTime": "t", "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "userIdentity": {"type": "Root"}}
    assert leastpriv.usage_from_cloudtrail([r]) == {}


@pytest.mark.slow
def test_real_universe_is_large_enough_to_make_a_wildcard_look_like_one():
    snap, u = usage()
    r = leastpriv.analyse(snap, u, Universe())
    assert r["granted_before"] > 10000 and r["reduction_pct"] > 99.9


def test_iam_names_that_differ_from_botocore_operations_are_in_the_real_universe():
    """Found by the first run on the real universe: s3:ListAllMyBuckets is the operation ListBuckets, so it was counted as nothing."""
    from aegis_sentinel.actions import SPECIAL
    real = Universe().actions("s3")
    assert {a for a in SPECIAL.values() if a.startswith("s3:")} <= real
