import importlib.util
from pathlib import Path

import pytest
from aegis_respond.clients import Clients
from aegis_respond.engine import Outcome
from aegis_respond.incident import Incident
from rsupport import MOTO_ACCOUNT, cloudtrail, findings_for
from moto import mock_aws

spec = importlib.util.spec_from_file_location("measure", Path(__file__).resolve().parents[1] / "tools" / "measure.py")
measure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measure)

SC = {"id": "S11", "technique": "T1555.006", "name": "Harvest secrets"}


def outcome(status="CONTAINED", contained=106.0, verified=106.4, wait=0.0):
    from aegis_respond.approval import Decision
    inc = Incident.from_asff(findings_for([cloudtrail("GetSecretValue", "secretsmanager", req={"secretId": "x"})], detected_after_s=0)[0])
    base = inc.event_time.timestamp()
    return Outcome(status, "", inc, "leaked_key", Decision(True, "x", "y", waited_s=wait),
                   t={"received": base + 1, "contained": base + contained - 100, "verified": base + verified - 100}), base


def test_row_times_are_measured_from_the_attack_start():
    out, base = outcome(contained=103.0, wait=1.0)
    row = measure.row_from("leaked_key", SC, base - 0.5, out, True, "auto")
    assert row["contained"] and row["mttd_s"] == 0.5 and row["attack_to_contained_s"] == 3.5
    assert row["detected_to_contained_s"] == 3.0 and row["machine_s"] == 2.0 and row["human_wait_s"] == 1.0


def test_a_missing_response_is_a_failure_not_a_gap():
    row = measure.row_from("leaked_key", SC, 0.0, None, None, "auto")
    assert row["status"] == "NO_RESPONSE" and not row["contained"] and "attack_to_contained_s" not in row


def test_contained_requires_independent_state_verification():
    out, base = outcome()
    assert not measure.row_from("leaked_key", SC, base, out, False, "auto")["contained"]   # responder said yes, state says no


def test_summary_and_headline_label_simulated_approval():
    out, base = outcome(contained=102.0)
    rows = [measure.row_from("leaked_key", SC, base, out, True, "auto"), measure.row_from("public_bucket", SC, base, None, None, "auto")]
    s = measure.summarize(rows)
    assert s["contained"] == 1 and s["pairs"] == 2 and s["mean_attack_to_contained_s"] == 2.0
    h = measure.headline(s, "auto")
    assert "1 of 2" in h and "simulated approval" in h
    md = measure.render_markdown("l", "now", rows, s, "auto")
    assert "approval in this run was automated" in md and "NO_RESPONSE" in md
    assert "real person" in measure.headline(s, "telegram")


def test_empty_summary_does_not_divide_by_zero():
    s = measure.summarize([])
    assert s["contained"] == 0 and s["mean_machine_s"] is None
    assert "-" in measure.headline(s, "auto")


@pytest.fixture
def rng():
    with mock_aws():
        admin = Clients(MOTO_ACCOUNT)
        iam, s3 = admin.get("iam"), admin.get("s3")
        iam.create_user(UserName="dev-svc")
        key = iam.create_access_key(UserName="dev-svc")["AccessKey"]["AccessKeyId"]
        s3.create_bucket(Bucket="data")
        s3.put_public_access_block(Bucket="data", PublicAccessBlockConfiguration=measure.BPA_ALL_ON)
        target = {"account_id": MOTO_ACCOUNT, "resources": {"data_bucket": "data"}, "credentials": {"attacker_key_id": key}, "name": "purple"}
        r = measure.Range(target, None)
        yield r


def test_range_reset_undoes_containment_and_rotation(rng):
    iam = rng.admin.get("iam")
    iam.update_access_key(UserName="dev-svc", AccessKeyId=rng.attacker_key, Status="Inactive")
    extra = iam.create_access_key(UserName="dev-svc")["AccessKey"]["AccessKeyId"]
    rng.admin.get("secretsmanager").create_secret(Name=f"aegis/rotated-access-key/{MOTO_ACCOUNT}/dev-svc", SecretString="x")
    assert rng.key_is_inactive() and rng.verify("leaked_key")
    rng.reset()
    ids = {k["AccessKeyId"]: k["Status"] for k in iam.list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]}
    assert ids == {rng.attacker_key: "Active"} and extra not in ids and not rng.key_is_inactive()
    rng.reset()                                                                   # idempotent: no secret left to delete


def test_range_bucket_check_sees_public_and_private(rng):
    assert rng.bucket_is_private()
    rng.admin.get("s3").put_public_access_block(Bucket="data", PublicAccessBlockConfiguration={k: False for k in measure.BPA_ALL_ON})
    assert not rng.bucket_is_private() and not rng.verify("public_bucket")
