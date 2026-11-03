"""Replay a synthetic run of the 12 attacks through the engine and the Stage 3 scorer.

This proves the RULE LOGIC and the attribution logic on events shaped like real CloudTrail. It does NOT
prove what LocalStack records: that is `make detect-probe` and the real `make stage3-run`.
The variants show how each documented miss arises when a telemetry source is missing."""
import json
import sys
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "cloudpurple"))

from attacks.attribution import attribute_alerts  # noqa: E402
from aegis_detect.asff import to_alert  # noqa: E402
from aegis_detect.engine import Engine  # noqa: E402
from aegis_detect.model import Event, iso  # noqa: E402
from helpers import ACCT, T0, rec  # noqa: E402

CLI = "Boto3/1.34.0 Botocore/1.34.0 aws-cli/2.17.0 some-other-machine"
POLICY = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
          "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]}
ADMIN_ALL = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def scenario_events(sid, t, *, data_events=True, stop_event=True, user_agent=True):
    """(attacker events, cleanup events) for one scenario starting at offset t seconds."""
    r = lambda *a, **k: rec(*a, at=t + k.pop("dt", 0.5), **k)  # noqa: E731
    root = dict(who="root", ua="cloudpurple-admin")
    ev, cl = [], []
    if sid == "S01":
        ev = [r("ListBuckets", "s3"), r("DescribeInstances", "ec2", dt=1), r("ListUsers", "iam", dt=1.5),
              r("DescribeSecurityGroups", "ec2", dt=2)]
    elif sid == "S02" and data_events:
        ev = [r("GetObject", "s3", dt=0.5 + i * 0.1, category="Data", req={"bucketName": "b", "key": f"k{i}"}) for i in range(12)]
    elif sid == "S03":
        ev = [r("CreateUser", "iam", req={"userName": "backdoor-1"}), r("AttachUserPolicy", "iam", dt=1),
              r("CreateAccessKey", "iam", dt=1.5)]
        cl = [r("DeleteUser", "iam", dt=3, req={"userName": "backdoor-1"}, **root)]
    elif sid == "S04":
        ev = [r("StopLogging", "cloudtrail", req={"name": "purple-trail"})] if stop_event else []
        cl = [r("StartLogging", "cloudtrail", dt=13, **root)]
    elif sid == "S05":
        ev = [r("AuthorizeSecurityGroupIngress", "ec2", req={"groupId": "sg-1", "ipPermissions": {"items": [
            {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})]
        cl = [r("RevokeSecurityGroupIngress", "ec2", dt=3, **root)]
    elif sid == "S06":
        ev = [r("PutBucketPolicy", "s3", req={"bucketName": "b", "bucketPolicy": POLICY})]
        cl = [r("DeleteBucketPolicy", "s3", dt=3, **root)]
    elif sid == "S07":
        ev = [r("PutPublicAccessBlock", "s3", req={"bucketName": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}),
              r("PutBucketAcl", "s3", dt=1, req={"bucketName": "b", "x-amz-acl": "public-read"})]
        cl = [r("PutBucketAcl", "s3", dt=3, req={"bucketName": "b", "AccessControlPolicy": {"Owner": {"ID": "x"}}}, **root),
              r("PutPublicAccessBlock", "s3", dt=3.5, req={"bucketName": "b", "PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}, **root)]
    elif sid == "S08":
        ua = CLI if user_agent else "Boto3/1.34.0 Botocore/1.34.0"
        ev = [r("GetCallerIdentity", "sts", ua=ua), r("ListBuckets", "s3", dt=1, ua=ua)]
    elif sid == "S09":
        ev = [r("CreatePolicyVersion", "iam", who="intern", req={"policyArn": f"arn:aws:iam::{ACCT}:policy/intern-policy",
              "setAsDefault": True, "policyDocument": json.dumps(ADMIN_ALL)}), r("ListUsers", "iam", dt=1, who="intern")]
        cl = [r("DeletePolicyVersion", "iam", dt=3, **root), r("SetDefaultPolicyVersion", "iam", dt=3.5, **root)]
    elif sid == "S10":
        ev = [r("ScheduleKeyDeletion", "kms", req={"keyId": "k1"})]
        cl = [r("CancelKeyDeletion", "kms", dt=3, **root)]
    elif sid == "S11":
        ev = [r("GetSecretValue", "secretsmanager", req={"secretId": "purple/db-password"})]
    elif sid == "S12":
        ev = [r("PutBucketVersioning", "s3", req={"bucketName": "b", "VersioningConfiguration": {"Status": "Suspended"}})]
        if data_events:
            ev += [r("DeleteObject", "s3", dt=1 + i * 0.1, category="Data", req={"bucketName": "b", "key": f"k{i}"}) for i in range(12)]
        cl = [r("PutBucketVersioning", "s3", dt=4, req={"bucketName": "b", "VersioningConfiguration": {"Status": "Enabled"}}, **root)]
    return ev, cl


SCENARIOS = [("S01", "T1580"), ("S02", "T1530"), ("S03", "T1136.003"), ("S04", "T1562.008"), ("S05", "T1562.007"),
             ("S06", "T1537"), ("S07", "T1530"), ("S08", "T1078.004"), ("S09", "T1098"), ("S10", "T1485"),
             ("S11", "T1555.006"), ("S12", "T1490")]


def simulate(**flags):
    records, rows = [], []
    for i, (sid, technique) in enumerate(SCENARIOS):
        t = i * 20.0
        ev, cl = scenario_events(sid, t, **flags)
        records += ev + cl
        rows.append({"id": sid, "technique": technique, "attack_start": iso(T0 + timedelta(seconds=t)),
                     "attack_end": iso(T0 + timedelta(seconds=t + 15)), "hardened": {"outcome": "SUCCEEDED"},
                     "purple": {"outcome": "SUCCEEDED"}})
        # the state poller sees the trail off while S04 is running (every 3 s, until cleanup)
        if sid == "S04":
            records += [{"__obs__": t + 1 + 3 * k} for k in range(4)]
    eng, events = Engine(), []
    for r in records:
        if "__obs__" in r:
            events.append(Event.observation("TrailStateObserved", ACCT, T0 + timedelta(seconds=r["__obs__"]),
                                            trail="purple-trail", isLogging=False))
        else:
            events.append(Event.from_cloudtrail(r, ACCT))
    alerts = []
    for det in eng.process(events):
        det.detected_at = det.event_time + timedelta(seconds=3)       # a 3 s poll lag
        alerts.append(to_alert(det))
    extras = attribute_alerts(rows, alerts, ACCT, 120)
    return {r["id"]: r for r in rows}, extras


def test_all_twelve_are_detected_when_telemetry_is_complete():
    rows, extras = simulate()
    missed = [k for k, r in rows.items() if not r["detected"]]
    assert not missed, missed
    assert all(1 <= r["mttd"] <= 5 for r in rows.values())


def test_without_data_events_exfiltration_is_the_documented_miss():
    rows, _ = simulate(data_events=False)
    assert [k for k, r in rows.items() if not r["detected"]] == ["S02"]


def test_state_polling_saves_s04_when_the_stop_event_was_never_recorded():
    rows, _ = simulate(stop_event=False)
    assert rows["S04"]["detected"] and rows["S04"]["alert_rule"] == "AEG-EVAS-002"


def test_without_user_agent_telemetry_s08_is_missed():
    rows, _ = simulate(user_agent=False)
    assert [k for k, r in rows.items() if not r["detected"]] == ["S08"]


def test_s02_is_not_credited_with_s07s_alert_when_data_events_are_missing():
    rows, _ = simulate(data_events=False)
    assert rows["S07"]["detected"] and not rows["S02"]["detected"]


def test_benign_cleanup_by_root_raises_nothing_but_the_bulk_delete_is_reported():
    _, extras = simulate()
    assert set(extras["other_by_rule"]) <= {"AEG-IMPACT-003", "AEG-EVAS-002", "AEG-EXFIL-003", "AEG-EXFIL-002"}