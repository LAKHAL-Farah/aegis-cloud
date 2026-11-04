import json

import pytest
from aegis_respond.clients import Clients
from aegis_respond.incident import Incident
from aegis_respond.playbooks import PLAYBOOKS, PlaybookRefusal
from aegis_respond.playbooks.public_bucket import ALL_ON
from aegis_respond.policy import ResponsePolicy
from rsupport import MOTO_ACCOUNT, cloudtrail, findings_for
from moto import mock_aws

POLICY = ResponsePolicy.load()


@pytest.fixture
def aws():
    with mock_aws():
        yield Clients(MOTO_ACCOUNT)


def new_user(aws, name="dev-svc", keys=1):
    iam = aws.get("iam")
    iam.create_user(UserName=name)
    return [iam.create_access_key(UserName=name)["AccessKey"] for _ in range(keys)]


def incident_for(key_id="AKIAEXAMPLEKEY0001", who="dev-svc", principal_arn=None, acct=MOTO_ACCOUNT):
    rec = cloudtrail("GetSecretValue", "secretsmanager", who=who, key=key_id, req={"secretId": "prod/db"}, acct=acct,
                     principal_arn=principal_arn)
    return Incident.from_asff(findings_for([rec], acct)[0])


# ---------------- leaked key
def test_plan_targets_exactly_the_key_named_in_the_log(aws):
    k1, = new_user(aws)
    plan = PLAYBOOKS["leaked_key"].plan(incident_for(k1["AccessKeyId"]), aws, POLICY)
    assert plan.targets["deactivate"] == [k1["AccessKeyId"]] and "exact" in plan.facts["match"]
    assert any("Deactivate" in s for s in plan.summary) and any("replacement" in s for s in plan.summary)


def test_plan_falls_back_to_all_active_keys_when_the_log_key_is_not_the_users(aws):
    """LocalStack records the account id as the access key id (docs/evidence/telemetry-probe.md)."""
    k1, = new_user(aws)
    plan = PLAYBOOKS["leaked_key"].plan(incident_for(MOTO_ACCOUNT), aws, POLICY)
    assert plan.targets["deactivate"] == [k1["AccessKeyId"]] and "all active" in plan.facts["match"]


def test_plan_is_read_only(aws):
    k1, = new_user(aws)
    PLAYBOOKS["leaked_key"].plan(incident_for(k1["AccessKeyId"]), aws, POLICY)
    keys = aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]
    assert [k["Status"] for k in keys] == ["Active"] and len(keys) == 1


def test_contain_deactivates_rotates_and_verifies(aws):
    k1, = new_user(aws)
    pb, inc = PLAYBOOKS["leaked_key"], incident_for(k1["AccessKeyId"])
    plan = pb.plan(inc, aws, POLICY)
    steps = pb.contain(inc, aws, plan, POLICY)
    assert all(s.ok for s in steps) and [s.name.split(":")[0] for s in steps] == ["deactivate", "rotate"]
    status = {k["AccessKeyId"]: k["Status"] for k in aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]}
    assert status[k1["AccessKeyId"]] == "Inactive" and list(status.values()).count("Active") == 1
    secret = json.loads(aws.get("secretsmanager").get_secret_value(
        SecretId=f"aegis/rotated-access-key/{MOTO_ACCOUNT}/dev-svc")["SecretString"])
    assert secret["AccessKeyId"] in status and status[secret["AccessKeyId"]] == "Active"
    assert pb.verify(inc, aws, plan).ok


def test_step_data_never_holds_the_new_secret(aws):
    k1, = new_user(aws)
    pb, inc = PLAYBOOKS["leaked_key"], incident_for(k1["AccessKeyId"])
    steps = pb.contain(inc, aws, pb.plan(inc, aws, POLICY), POLICY)
    secret = json.loads(aws.get("secretsmanager").get_secret_value(
        SecretId=f"aegis/rotated-access-key/{MOTO_ACCOUNT}/dev-svc")["SecretString"])["SecretAccessKey"]
    assert secret not in json.dumps([(s.detail, s.data) for s in steps])


def test_rotation_is_skipped_when_the_user_already_has_two_keys(aws):
    k1, k2 = new_user(aws, keys=2)
    pb, inc = PLAYBOOKS["leaked_key"], incident_for(k1["AccessKeyId"])
    plan = pb.plan(inc, aws, POLICY)
    assert [a["op"] for a in plan.targets["actions"]] == ["deactivate"] and any("limit" in s for s in plan.summary)
    pb.contain(inc, aws, plan, POLICY)
    st = {k["AccessKeyId"]: k["Status"] for k in aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]}
    assert st[k1["AccessKeyId"]] == "Inactive" and st[k2["AccessKeyId"]] == "Active"


def test_a_failed_secret_store_deletes_the_orphan_key(aws, monkeypatch):
    k1, = new_user(aws)
    pb, inc = PLAYBOOKS["leaked_key"], incident_for(k1["AccessKeyId"])
    plan = pb.plan(inc, aws, POLICY)
    sm = aws.get("secretsmanager")

    def boom(**kw):
        from botocore.exceptions import ClientError
        raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "CreateSecret")
    monkeypatch.setattr(sm, "create_secret", boom)
    steps = pb.contain(inc, aws, plan, POLICY)
    assert steps[0].ok and not steps[1].ok and "was deleted" in steps[1].detail
    assert len(aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]) == 1     # contained, no orphan


def test_roles_and_foreign_accounts_are_refused(aws):
    new_user(aws)
    role = incident_for(principal_arn=f"arn:aws:sts::{MOTO_ACCOUNT}:assumed-role/ops/session")
    with pytest.raises(PlaybookRefusal, match="not an IAM user"):
        PLAYBOOKS["leaked_key"].plan(role, aws, POLICY)
    other = incident_for(principal_arn="arn:aws:iam::999999999999:user/dev-svc")
    with pytest.raises(PlaybookRefusal, match="cross-account"):
        PLAYBOOKS["leaked_key"].plan(other, aws, POLICY)


def test_a_deleted_user_is_refused_not_crashed(aws):
    with pytest.raises(PlaybookRefusal, match="no longer exists"):
        PLAYBOOKS["leaked_key"].plan(incident_for(), aws, POLICY)


def test_user_with_no_active_keys_is_a_noop(aws):
    k1, = new_user(aws)
    aws.get("iam").update_access_key(UserName="dev-svc", AccessKeyId=k1["AccessKeyId"], Status="Inactive")
    plan = PLAYBOOKS["leaked_key"].plan(incident_for(k1["AccessKeyId"]), aws, POLICY)
    assert not plan.actionable and "Nothing to do" in plan.summary[0]


# ---------------- public bucket
def make_public(aws, bucket="data-bucket"):
    s3 = aws.get("s3")
    s3.create_bucket(Bucket=bucket)
    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={k: False for k in ALL_ON})
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    return s3


def bucket_incident(bucket="data-bucket"):
    return Incident.from_asff(findings_for([cloudtrail("PutPublicAccessBlock", "s3", req={
        "bucketName": bucket, "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}})])[0])


def test_public_bucket_is_made_private_and_verified(aws):
    s3 = make_public(aws)
    pb, inc = PLAYBOOKS["public_bucket"], bucket_incident()
    plan = pb.plan(inc, aws, POLICY)
    assert len(plan.targets["actions"]) == 2 and "AllUsers" in " ".join(plan.summary)
    assert not pb.verify(inc, aws, plan).ok                         # before: not private
    steps = pb.contain(inc, aws, plan, POLICY)
    assert all(s.ok for s in steps) and pb.verify(inc, aws, plan).ok
    assert s3.get_public_access_block(Bucket="data-bucket")["PublicAccessBlockConfiguration"] == ALL_ON


def test_already_private_bucket_is_a_noop(aws):
    s3 = aws.get("s3")
    s3.create_bucket(Bucket="data-bucket")
    s3.put_public_access_block(Bucket="data-bucket", PublicAccessBlockConfiguration=ALL_ON)
    assert not PLAYBOOKS["public_bucket"].plan(bucket_incident(), aws, POLICY).actionable


def test_missing_or_unnamed_bucket_is_refused(aws):
    with pytest.raises(PlaybookRefusal, match="no longer exists"):
        PLAYBOOKS["public_bucket"].plan(bucket_incident("ghost"), aws, POLICY)
    with pytest.raises(PlaybookRefusal, match="does not name"):
        PLAYBOOKS["public_bucket"].plan(bucket_incident("unknown"), aws, POLICY)


def test_public_bucket_rollback_is_never_automatic(aws):
    assert not PLAYBOOKS["public_bucket"].rollback(aws, [])[0].ok


def test_playbooks_match_by_detection_rule_only_when_enabled():
    inc = bucket_incident()
    assert PLAYBOOKS["public_bucket"].matches(inc, POLICY) and not PLAYBOOKS["leaked_key"].matches(inc, POLICY)
    off = ResponsePolicy.load()
    off.playbooks["public_bucket"]["enabled"] = False
    assert not PLAYBOOKS["public_bucket"].matches(inc, off)
