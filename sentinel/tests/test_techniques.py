import pytest
from aegis_sentinel.escalation import CATALOGUE, scan
from support import allow, arn, doc, snap, trust_root, trust_service, trust_user

ADMIN_DOC = doc(allow("*"))


def result(s, name, policy=None):
    r = scan(s, policy or {"expected_admins": []})
    return next(p for p in r["principals"].values() if p["name"] == name)


def techniques(r):
    return [step["technique"] for step in r["path"]]


@pytest.mark.parametrize("action,tid", [
    ("iam:AttachUserPolicy", "ESC-03"), ("iam:PutUserPolicy", "ESC-04")])
def test_editing_your_own_user_policies_is_admin(action, tid):
    r = result(snap(users=[("u", {"inline": {"p": doc(allow(action, arn("user", "u")))}})]), "u")
    assert r["category"] == "escalates" and techniques(r) == [tid]


def test_scoping_to_someone_else_is_not_an_escalation():
    r = result(snap(users=[("u", {"inline": {"p": doc(allow("iam:AttachUserPolicy", arn("user", "somebody-else")))}}),
                           ("somebody-else", {})]), "u")
    assert r["category"] == "ordinary"


def test_group_policy_edit_works_for_members_only():
    s = snap(users=[("member", {"groups": ["devs"]}), ("outsider", {})],
             groups=[("devs", {"inline": {"p": doc(allow("iam:PutGroupPolicy", arn("group", "devs")))}})])
    assert techniques(result(s, "member")) == ["ESC-04"]
    assert result(s, "outsider")["category"] == "ordinary"


def test_create_policy_version_needs_the_policy_to_be_attached_to_the_caller():
    p = doc(allow("iam:CreatePolicyVersion", arn("policy", "mine")))
    mine = snap(users=[("u", {"attached": [arn("policy", "mine")]})], policies=[("mine", {"doc": p})])
    assert techniques(result(mine, "u")) == ["ESC-01"]
    other = snap(users=[("u", {"inline": {"x": p}}), ("v", {"attached": [arn("policy", "mine")]})], policies=[("mine", {"doc": doc(allow("s3:GetObject"))})])
    assert result(other, "u")["category"] == "ordinary"          # the policy is not attached to u: u can only change what v gets


def test_aws_managed_policies_cannot_be_edited():
    p = arn("policy", "managed")
    s = snap(users=[("u", {"attached": [p], "inline": {"x": doc(allow("iam:CreatePolicyVersion", p))}})],
             policies=[("managed", {"doc": doc(allow("s3:GetObject")), "aws_managed": True})])
    assert result(s, "u")["category"] == "ordinary"


def test_set_default_version_only_counts_when_an_old_version_is_wider():
    p = arn("policy", "mine")
    can = doc(allow("iam:SetDefaultPolicyVersion", p))
    narrow = snap(users=[("u", {"attached": [p]})], policies=[("mine", {"doc": can, "other_versions": [doc(allow("s3:GetObject"))]})])
    wide = snap(users=[("u", {"attached": [p]})], policies=[("mine", {"doc": can, "other_versions": [ADMIN_DOC]})])
    assert result(narrow, "u")["category"] == "ordinary"
    assert techniques(result(wide, "u")) == ["ESC-02"]


def test_access_key_and_login_profile_on_another_user_chain_to_admin():
    s = snap(users=[("a", {"inline": {"p": doc(allow("iam:CreateAccessKey", arn("user", "b")))}}),
                    ("b", {"inline": {"p": ADMIN_DOC}}), ("c", {"inline": {"p": doc(allow("iam:UpdateLoginProfile", arn("user", "b")))}})])
    assert techniques(result(s, "a")) == ["ESC-06", "ADMIN"]
    assert techniques(result(s, "c")) == ["ESC-07", "ADMIN"]


def test_a_two_hop_chain_is_found_and_reported_with_its_length():
    s = snap(users=[("a", {"inline": {"p": doc(allow("iam:CreateAccessKey", arn("user", "b")))}}),
                    ("b", {"inline": {"p": doc(allow("sts:AssumeRole", arn("role", "r")))}})],
             roles=[("r", {"trust": trust_root(), "attached": [arn("policy", "adm")]})],
             policies=[("adm", {"doc": ADMIN_DOC})])
    r = result(s, "a")
    assert r["category"] == "escalates" and r["hops"] == 3 and techniques(r) == ["ESC-06", "ESC-09", "ADMIN"]


def test_root_trust_alone_is_not_enough_but_naming_the_user_is():
    role = ("r", {"attached": [arn("policy", "adm")]})
    pol = [("adm", {"doc": ADMIN_DOC})]
    delegated = snap(users=[("u", {})], roles=[("r", {**role[1], "trust": trust_root()})], policies=pol)
    named = snap(users=[("u", {})], roles=[("r", {**role[1], "trust": trust_user("u")})], policies=pol)
    allowed = snap(users=[("u", {"inline": {"p": doc(allow("sts:AssumeRole", arn("role", "r")))}})],
                   roles=[("r", {**role[1], "trust": trust_root()})], policies=pol)
    assert result(delegated, "u")["category"] == "ordinary"
    assert techniques(result(named, "u")) == ["ESC-09", "ADMIN"]
    assert techniques(result(allowed, "u")) == ["ESC-09", "ADMIN"]


def test_a_trust_condition_marks_the_path_conditional_not_absent():
    s = snap(users=[("u", {"inline": {"p": doc(allow("sts:AssumeRole", "*"))}})],
             roles=[("r", {"trust": trust_root(Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}}), "attached": [arn("policy", "adm")]})],
             policies=[("adm", {"doc": ADMIN_DOC})])
    r = result(s, "u")
    assert r["category"] == "escalates" and r["path"][0]["conditional"] is True


def test_rewriting_a_trust_policy_is_a_path():
    s = snap(users=[("u", {"inline": {"p": doc(allow("iam:UpdateAssumeRolePolicy", arn("role", "r")))}})],
             roles=[("r", {"trust": trust_service("ec2.amazonaws.com"), "attached": [arn("policy", "adm")]})], policies=[("adm", {"doc": ADMIN_DOC})])
    assert techniques(result(s, "u")) == ["ESC-08", "ADMIN"]


@pytest.mark.parametrize("service,needs,tid", [
    ("lambda.amazonaws.com", ["lambda:CreateFunction", "lambda:InvokeFunction"], "ESC-10"),
    ("ec2.amazonaws.com", ["ec2:RunInstances"], "ESC-11"),
    ("cloudformation.amazonaws.com", ["cloudformation:CreateStack"], "ESC-12")])
def test_pass_role_needs_the_service_to_trust_the_role_and_the_launch_permission(service, needs, tid):
    role = ("r", {"trust": trust_service(service), "attached": [arn("policy", "adm")]})
    pol = [("adm", {"doc": ADMIN_DOC})]
    full = snap(users=[("u", {"inline": {"p": doc(allow(["iam:PassRole", *needs], "*"))}})], roles=[role], policies=pol)
    no_launch = snap(users=[("u", {"inline": {"p": doc(allow("iam:PassRole", "*"))}})], roles=[role], policies=pol)
    wrong_service = snap(users=[("u", {"inline": {"p": doc(allow(["iam:PassRole", *needs], "*"))}})],
                         roles=[("r", {"trust": trust_service("glue.amazonaws.com"), "attached": [arn("policy", "adm")]})], policies=pol)
    assert techniques(result(full, "u")) == [tid, "ADMIN"]
    assert result(no_launch, "u")["category"] == "ordinary"
    assert result(wrong_service, "u")["category"] == "ordinary"


def test_adding_yourself_to_an_admin_group_is_a_path_but_not_to_a_harmless_one():
    s = snap(users=[("u", {"inline": {"p": doc(allow("iam:AddUserToGroup", "*"))}})],
             groups=[("admins", {"inline": {"p": ADMIN_DOC}}), ("readers", {"inline": {"p": doc(allow("s3:GetObject"))}})])
    assert techniques(result(s, "u")) == ["ESC-05"]
    only_readers = snap(users=[("u", {"inline": {"p": doc(allow("iam:AddUserToGroup", arn("group", "readers")))}})],
                        groups=[("admins", {"inline": {"p": ADMIN_DOC}}), ("readers", {"inline": {"p": doc(allow("s3:GetObject"))}})])
    assert result(only_readers, "u")["category"] == "ordinary"


# ---- permission boundaries: the most common place for a small evaluator to be wrong
BOUNDARY = doc(allow(["s3:*", "iam:AttachUserPolicy"], "*"))


def test_a_boundary_that_does_not_allow_the_action_removes_the_path():
    s = snap(users=[("u", {"boundary": arn("policy", "b"), "inline": {"p": doc(allow("iam:PutUserPolicy", arn("user", "u")))}})],
             policies=[("b", {"doc": BOUNDARY})])
    assert result(s, "u")["category"] == "ordinary"


def test_a_boundary_that_allows_the_grant_caps_it_instead_of_making_the_user_admin():
    s = snap(users=[("u", {"boundary": arn("policy", "b"), "inline": {"p": doc(allow("iam:AttachUserPolicy", arn("user", "u")))}})],
             policies=[("b", {"doc": BOUNDARY})])
    r = result(s, "u")
    assert r["category"] == "capped" and r["capped"] == ["ESC-03"]    # it can attach, but the ceiling still applies


def test_removing_the_boundary_is_a_path_when_the_identity_policy_is_a_wildcard():
    s = snap(users=[("u", {"boundary": arn("policy", "b"), "inline": {"p": ADMIN_DOC}})], policies=[("b", {"doc": doc(allow(["s3:*", "iam:DeleteUserPermissionsBoundary"]))})])
    assert techniques(result(s, "u")) == ["ESC-13"]
    denied = snap(users=[("u", {"boundary": arn("policy", "b"), "inline": {"p": ADMIN_DOC}})],
                  policies=[("b", {"doc": doc(allow(["s3:*", "iam:DeleteUserPermissionsBoundary"]),
                                              {"Effect": "Deny", "Action": "iam:DeleteUserPermissionsBoundary", "Resource": "*"})})])
    assert result(denied, "u")["category"] == "ordinary"      # the boundary denies removing itself, and caps the wildcard


def test_an_explicit_deny_beats_an_allow():
    s = snap(users=[("u", {"inline": {"p": doc(allow("iam:PutUserPolicy", "*"),
                                               {"Effect": "Deny", "Action": "iam:PutUserPolicy", "Resource": "*"})}})])
    assert result(s, "u")["category"] == "ordinary"


def test_a_conditional_deny_does_not_hide_a_path():
    s = snap(users=[("u", {"inline": {"p": doc(allow("iam:PutUserPolicy", "*"),
                                               {"Effect": "Deny", "Action": "iam:PutUserPolicy", "Resource": "*",
                                                "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}})}})])
    assert result(s, "u")["category"] == "escalates"     # the condition is not evaluated, so the path is kept and may be a false positive


def test_not_action_policies_are_not_mistaken_for_admin():
    power = doc(allow(None, "*", **{}))
    power["Statement"] = [{"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}]
    s = snap(users=[("u", {"inline": {"p": power}})])
    assert result(s, "u")["category"] == "ordinary"       # PowerUser-style: wide but not able to edit IAM


def test_expected_admins_are_listed_not_flagged():
    s = snap(roles=[("break-glass", {"trust": trust_root(), "attached": [arn("policy", "adm")]})], policies=[("adm", {"doc": ADMIN_DOC})])
    assert result(s, "break-glass", {"expected_admins": ["*break-glass*"]})["category"] == "expected_admin"
    assert result(s, "break-glass", {"expected_admins": []})["category"] == "admin"


def test_every_technique_has_a_fix_and_an_attack_id():
    for tid, c in CATALOGUE.items():
        assert c["fix"] and c["name"] and c["attack"].startswith("T"), tid


def test_scan_reports_what_it_could_not_resolve():
    s = snap(users=[("u", {"attached": ["arn:aws:iam::aws:policy/SomethingUnknown"]})])
    s["unresolved"] = ["arn:aws:iam::aws:policy/SomethingUnknown"]
    assert scan(s, {"expected_admins": []})["unresolved"] == ["arn:aws:iam::aws:policy/SomethingUnknown"]
