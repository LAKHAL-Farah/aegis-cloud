"""One positive and at least one negative case per rule, on synthetic CloudTrail records."""
import json
from datetime import timedelta

from aegis_detect.engine import Engine
from aegis_detect.model import Event
from helpers import ACCT, T0, rec


def run(*records, now=None):
    eng = Engine()
    dets = eng.process([Event.from_cloudtrail(r, ACCT) for r in records])
    return dets


def ids(dets):
    return {d.rule_id for d in dets}


# ------------------------------------------------------------ discovery
def test_discovery_burst_fires_on_multi_service_listing():
    dets = run(rec("ListBuckets", "s3", at=0), rec("DescribeInstances", "ec2", at=1),
               rec("ListUsers", "iam", at=2), rec("DescribeSecurityGroups", "ec2", at=3))
    assert ids(dets) == {"AEG-DISC-001"} and dets[0].technique == "T1580"


def test_discovery_needs_several_services():
    dets = run(*[rec("DescribeInstances", "ec2", at=i) for i in range(6)])
    assert not dets


def test_discovery_ignores_other_principals_mixed_in():
    dets = run(rec("ListBuckets", "s3", at=0, who="a"), rec("DescribeInstances", "ec2", at=1, who="b"),
               rec("ListUsers", "iam", at=2, who="c"), rec("DescribeSecurityGroups", "ec2", at=3, who="d"))
    assert not dets


# ------------------------------------------------------------ persistence
def test_create_user_alerts():
    d = run(rec("CreateUser", "iam", req={"userName": "backdoor-x"}))
    assert ids(d) == {"AEG-PERS-001"} and d[0].resource_id == "backdoor-x"


def test_failed_create_user_is_not_an_alert():
    assert not run(rec("CreateUser", "iam", req={"userName": "x"}, error="AccessDenied"))


# ------------------------------------------------------------ evasion
def test_stop_logging_is_critical():
    d = run(rec("StopLogging", "cloudtrail", req={"name": "purple-trail"}))
    assert ids(d) == {"AEG-EVAS-001"} and d[0].severity == "critical" and d[0].technique == "T1562.008"


def test_trail_state_observation_alerts_only_when_off():
    eng = Engine()
    off = Event.observation("TrailStateObserved", ACCT, T0, trail="t", isLogging=False)
    on = Event.observation("TrailStateObserved", ACCT, T0 + timedelta(seconds=3), trail="t", isLogging=True)
    assert {d.rule_id for d in eng.process([on])} == set()
    assert {d.rule_id for d in eng.process([off])} == {"AEG-EVAS-002"}


def test_sg_open_ssh_alerts_and_internal_cidr_does_not():
    world = {"groupId": "sg-1", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22,
             "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
    inner = json.loads(json.dumps(world).replace("0.0.0.0/0", "10.0.0.0/8"))
    assert ids(run(rec("AuthorizeSecurityGroupIngress", "ec2", req=world))) == {"AEG-EVAS-003"}
    assert not run(rec("AuthorizeSecurityGroupIngress", "ec2", req=inner))


def test_sg_world_open_on_a_non_admin_port_is_ignored():
    web = {"groupId": "sg-1", "ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 443, "toPort": 443,
           "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
    assert not run(rec("AuthorizeSecurityGroupIngress", "ec2", req=web))


def test_sg_all_traffic_is_critical():
    allp = {"groupId": "sg-1", "ipPermissions": {"items": [{"ipProtocol": "-1",
            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}
    d = run(rec("AuthorizeSecurityGroupIngress", "ec2", req=allp))
    assert d and d[0].severity == "critical"


def test_interactive_client_on_service_identity():
    ua = "Boto3/1.34 Botocore/1.34 aws-cli/2.17.0 some-device"
    assert ids(run(rec("ListBuckets", "s3", ua=ua))) == {"AEG-ACCESS-001"}


def test_cli_on_a_human_identity_is_fine():
    assert not run(rec("ListBuckets", "s3", who="alice", ua="aws-cli/2.17.0"))


def test_sdk_on_service_identity_is_fine():
    assert not run(rec("ListBuckets", "s3", ua="Boto3/1.34 Botocore/1.34"))


# ------------------------------------------------------------ exfiltration / exposure
def policy_req(principal):
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": principal,
           "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}]}
    return {"bucketName": "b", "bucketPolicy": doc}


def test_bucket_policy_to_foreign_account():
    d = run(rec("PutBucketPolicy", "s3", req=policy_req({"AWS": "arn:aws:iam::999999999999:root"})))
    assert ids(d) == {"AEG-EXFIL-001"} and d[0].technique == "T1537"


def test_bucket_policy_to_own_account_is_fine():
    assert not run(rec("PutBucketPolicy", "s3", req=policy_req({"AWS": f"arn:aws:iam::{ACCT}:root"})))


def test_bucket_policy_to_everyone_is_critical_and_accepts_json_string():
    req = policy_req("*")
    req["bucketPolicy"] = json.dumps(req["bucketPolicy"])
    d = run(rec("PutBucketPolicy", "s3", req=req))
    assert d and d[0].severity == "critical"


def test_public_acl_and_relaxed_block():
    assert ids(run(rec("PutBucketAcl", "s3", req={"bucketName": "b", "x-amz-acl": "public-read"}))) == {"AEG-EXFIL-002"}
    off = {"bucketName": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "RestrictPublicBuckets": True}}
    assert ids(run(rec("PutPublicAccessBlock", "s3", req=off))) == {"AEG-EXFIL-002"}


def test_block_public_access_fully_on_is_fine():
    on = {"bucketName": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "RestrictPublicBuckets": True}}
    assert not run(rec("PutPublicAccessBlock", "s3", req=on))


def gets(n, who="dev-svc", start=0.0):
    return [rec("GetObject", "s3", who=who, at=start + i * 0.2, category="Data", read_only=True,
                req={"bucketName": "b", "key": f"customers/r{i}.csv"}) for i in range(n)]


def test_getobject_burst_needs_ten_distinct_objects():
    assert ids(run(*gets(12))) == {"AEG-EXFIL-003"}
    assert not run(*gets(9))


def test_getobject_burst_does_not_depend_on_the_event_category_label():
    # LocalStack labels some GetObject records "Management"
    assert ids(run(*[dict(r, eventCategory="Management") for r in gets(12)])) == {"AEG-EXFIL-003"}


def test_the_detector_reading_cloudtrail_log_files_is_not_an_exfiltration():
    logs = [rec("GetObject", "s3", who="root", at=i * 0.2, read_only=True, req={
        "bucketName": "purple-trail-555555555555",
        "key": f"AWSLogs/555555555555/CloudTrail/us-east-1/2026/11/03/f{i}.json.gz"}) for i in range(15)]
    assert not run(*logs)


# ------------------------------------------------------------ privilege escalation
def policy_version(who, doc=None):
    return rec("CreatePolicyVersion", "iam", who=who, req={
        "policyArn": f"arn:aws:iam::{ACCT}:policy/intern-policy", "setAsDefault": True,
        "policyDocument": json.dumps(doc or {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"}]})})


def test_policy_rewrite_by_non_admin_is_critical_when_it_grants_everything():
    d = run(policy_version("intern"))
    assert ids(d) == {"AEG-PRIV-001"} and d[0].severity == "critical"


def test_policy_rewrite_by_root_is_allowed():
    assert not run(policy_version("root"))


# ------------------------------------------------------------ impact
def test_key_deletion_and_versioning_and_delete_burst():
    assert ids(run(rec("ScheduleKeyDeletion", "kms", req={"keyId": "k1", "pendingWindowInDays": 7}))) == {"AEG-IMPACT-001"}
    sus = rec("PutBucketVersioning", "s3", req={"bucketName": "b", "VersioningConfiguration": {"Status": "Suspended"}})
    d = run(sus)
    assert ids(d) == {"AEG-IMPACT-002"} and d[0].technique == "T1490"
    enabled = rec("PutBucketVersioning", "s3", req={"bucketName": "b", "VersioningConfiguration": {"Status": "Enabled"}})
    assert not run(enabled)
    dels = [rec("DeleteObject", "s3", at=i * 0.2, category="Data", req={"bucketName": "b", "key": f"k{i}"}) for i in range(6)]
    assert ids(run(*dels)) == {"AEG-IMPACT-003"}


# ------------------------------------------------------------ credential access
def test_secret_read_alerts_unless_listed():
    r = rec("GetSecretValue", "secretsmanager", req={"secretId": "purple/db-password"})
    assert ids(run(r)) == {"AEG-CRED-001"}
    from aegis_detect.policy import Policy
    eng = Engine(Policy(secret_readers=["dev-svc"]))
    assert not eng.process([Event.from_cloudtrail(r, ACCT)])


def test_bucket_policy_with_an_unrecorded_body_still_alerts_at_medium():
    # LocalStack records requestParameters.policy as "" (see docs/evidence/telemetry-probe.md)
    d = run(rec("PutBucketPolicy", "s3", req={"bucketName": "b", "policy": ""}))
    assert ids(d) == {"AEG-EXFIL-001"} and d[0].severity == "medium" and d[0].technique == "T1537"
    assert "body not recorded" in d[0].title


def test_unrecorded_body_is_the_only_reason_for_the_fallback():
    assert not run(rec("PutBucketPolicy", "s3", req=policy_req({"AWS": f"arn:aws:iam::{ACCT}:root"})))


def test_delete_burst_does_not_depend_on_the_event_category_label():
    # LocalStack labels every S3 object event "Management"
    dels = [rec("DeleteObject", "s3", at=i * 0.2, req={"bucketName": "b", "key": f"k{i}"}) for i in range(6)]
    assert ids(run(*dels)) == {"AEG-IMPACT-003"}


def test_a_few_deletes_are_not_a_burst():
    dels = [rec("DeleteObject", "s3", at=i * 0.2, req={"bucketName": "b", "key": f"k{i}"}) for i in range(3)]
    assert not run(*dels)
