import json

import pytest
from aegis_respond.approval import AutoApprover, Decision
from aegis_respond.clients import Clients
from aegis_respond.engine import CONTAINED, DENIED, DRY_RUN, DUPLICATE, NOOP, REFUSED, REJECTED, SKIPPED, TIMEOUT
from aegis_respond.incident import Incident
from rsupport import MOTO_ACCOUNT, Approve, cloudtrail, findings_for
from moto import mock_aws


@pytest.fixture
def aws():
    with mock_aws():
        c = Clients(MOTO_ACCOUNT)
        c.get("iam").create_user(UserName="dev-svc")
        c.get("iam").create_access_key(UserName="dev-svc")
        yield c


def active_keys(aws, user="dev-svc"):
    return [k for k in aws.get("iam").list_access_keys(UserName=user)["AccessKeyMetadata"] if k["Status"] == "Active"]


def keyed(finding_fn=None, who="dev-svc", at=0.0):
    return findings_for([cloudtrail("GetSecretValue", "secretsmanager", who=who, at=at, req={"secretId": "prod/db"})])[0]


def test_dry_run_plans_notifies_and_changes_nothing(aws, make_responder, secret_finding):
    ap = Approve()
    r = make_responder(approver=ap, execute=False)
    out = r.handle(secret_finding)
    assert out.status == DRY_RUN and not ap.calls and len(active_keys(aws)) == 1
    assert "[dry run]" in r.notifier_ref.messages[0] and "Deactivate" in r.notifier_ref.messages[0]


def test_no_change_happens_before_approval(aws, make_responder, secret_finding):
    seen = []

    class Spy(Approve):
        def request(self, inc, plan, timeout_s):
            seen.append(len(active_keys(aws)))          # state at the moment the human is asked
            return super().request(inc, plan, timeout_s)

    make_responder(approver=Spy()).handle(secret_finding)
    assert seen == [1]


def test_denied_changes_nothing(aws, make_responder, secret_finding):
    r = make_responder(approver=Approve(ok=False, by="farah"))
    out = r.handle(secret_finding)
    assert out.status == DENIED and len(active_keys(aws)) == 1
    assert "No action taken" in r.notifier_ref.messages[-1]


def test_timeout_is_a_denial(aws, make_responder, secret_finding):
    class Silent:
        name = "silent"

        def request(self, inc, plan, timeout_s):
            return Decision(False, "timeout", "no tap", waited_s=timeout_s)
    out = make_responder(approver=Silent()).handle(secret_finding)
    assert out.status == TIMEOUT and len(active_keys(aws)) == 1


def test_a_crashing_approval_channel_fails_closed(aws, make_responder, secret_finding):
    class Broken:
        name = "broken"

        def request(self, *a):
            raise RuntimeError("telegram down")
    out = make_responder(approver=Broken()).handle(secret_finding)
    assert out.status == DENIED and "approval channel failed" in out.detail and len(active_keys(aws)) == 1


def test_approved_incident_is_contained_verified_and_timed(aws, make_responder, secret_finding):
    inc = Incident.from_asff(secret_finding)
    base = inc.detected_at.timestamp()
    ticks = iter([base + 1 + i * 0.5 for i in range(20)])
    r = make_responder(approver=Approve(waited=3.0), clock=lambda: next(ticks))
    out = r.handle(secret_finding)
    assert out.status == CONTAINED and out.playbook == "leaked_key"
    assert len(active_keys(aws)) == 1                                  # old key off, replacement on
    tm = out.timings()
    assert tm["human_wait_s"] == 3.0 and tm["detected_to_contained_s"] > 0
    assert tm["machine_s"] == pytest.approx(tm["detected_to_contained_s"] - 3.0)
    assert tm["event_to_contained_s"] == pytest.approx(tm["detected_to_contained_s"] + 2.0)   # finding was raised 2 s after the event
    assert "Contained" in r.notifier_ref.messages[-1]


def test_the_audit_trail_tells_the_whole_story_and_stays_intact(aws, make_responder, secret_finding):
    r = make_responder()
    r.handle(secret_finding)
    short = Incident.from_asff(secret_finding).short
    steps = [(x["step"].split(":")[0], x["status"]) for x in r.audit.records(short)]
    assert steps == [("received", "ok"), ("plan", "ok"), ("approval", "ok"), ("deactivate", "ok"), ("rotate", "ok"),
                     ("verify", "ok"), ("outcome", "contained")]
    assert r.audit.verify()[0]


def test_no_secret_key_material_reaches_the_audit_trail_or_chat(aws, make_responder, secret_finding):
    r = make_responder()
    r.handle(secret_finding)
    sm = aws.get("secretsmanager")
    secret = json.loads(sm.get_secret_value(SecretId=f"aegis/rotated-access-key/{MOTO_ACCOUNT}/dev-svc")["SecretString"])
    blob = r.audit.path.read_text() + "\n".join(r.notifier_ref.messages)
    assert secret["SecretAccessKey"] not in blob


def test_same_finding_twice_acts_once(aws, make_responder, secret_finding):
    r = make_responder()
    assert r.handle(secret_finding).status == CONTAINED
    assert r.handle(secret_finding).status == DUPLICATE


def test_a_new_finding_for_the_same_principal_inside_the_cooldown_is_suppressed(aws, make_responder):
    r = make_responder()
    assert r.handle(keyed(at=0)).status == CONTAINED
    out = r.handle(keyed(at=30))
    assert out.status == DUPLICATE and "cooldown" in out.detail


def test_protected_identities_are_never_touched_even_if_approved(aws, make_responder):
    aws.get("iam").create_user(UserName="aegis-responder")
    aws.get("iam").create_access_key(UserName="aegis-responder")
    ap = Approve()
    r = make_responder(approver=ap)
    out = r.handle(keyed(who="aegis-responder"))
    assert out.status == REFUSED and not ap.calls and len(active_keys(aws, "aegis-responder")) == 1
    assert "protected" in out.detail and "person" in r.notifier_ref.messages[-1]


def test_root_is_protected(aws, make_responder):
    f = findings_for([cloudtrail("GetSecretValue", "secretsmanager", who="root", req={"secretId": "x"},
                                 principal_arn=f"arn:aws:iam::{MOTO_ACCOUNT}:root")])[0]
    assert make_responder().handle(f).status == REFUSED


def test_playbook_refusals_are_explained_to_a_human(aws, make_responder):
    f = findings_for([cloudtrail("GetSecretValue", "secretsmanager", req={"secretId": "x"},
                                 principal_arn=f"arn:aws:sts::{MOTO_ACCOUNT}:assumed-role/ops/s")])[0]
    r = make_responder()
    out = r.handle(f)
    assert out.status == REFUSED and "not an IAM user" in r.notifier_ref.messages[-1]


def test_unmatched_and_low_severity_findings_are_skipped(aws, make_responder):
    kms = findings_for([cloudtrail("ScheduleKeyDeletion", "kms", req={"keyId": "k1"})])[0]     # no playbook for impact
    assert make_responder().handle(kms).status == SKIPPED
    low = json.loads(json.dumps(keyed()))
    low["Severity"]["Label"] = "LOW"
    assert make_responder().handle(low).status == SKIPPED


def test_garbage_is_rejected_and_audited(make_responder):
    r = make_responder()
    assert r.handle({"hello": "world"}).status == REJECTED
    assert r.audit.records()[0]["step"] == "rejected"


def test_a_dead_notification_channel_does_not_stop_containment(aws, make_responder, secret_finding):
    class Dead:
        name = "dead"

        def send(self, *a):
            raise RuntimeError("slack 500")
    r = make_responder(notifier=Dead())
    assert r.handle(secret_finding).status == CONTAINED
    assert any(x["step"] == "notify" and x["status"] == "error" for x in r.audit.records())


def test_partial_containment_is_reported_not_hidden(aws, make_responder, secret_finding, monkeypatch):
    from aegis_respond.playbooks import PLAYBOOKS
    from aegis_respond.playbooks.base import Step
    real = PLAYBOOKS["leaked_key"].verify
    monkeypatch.setattr(PLAYBOOKS["leaked_key"], "verify", lambda *a: Step("verify", False, "key still active"))
    r = make_responder()
    out = r.handle(secret_finding)
    assert out.status == "PARTIAL" and "needs a person" in r.notifier_ref.messages[-1]
    monkeypatch.setattr(PLAYBOOKS["leaked_key"], "verify", real)


def test_nothing_to_do_when_the_user_has_no_active_keys(aws, make_responder, secret_finding):
    for k in active_keys(aws):
        aws.get("iam").update_access_key(UserName="dev-svc", AccessKeyId=k["AccessKeyId"], Status="Inactive")
    assert make_responder().handle(secret_finding).status == NOOP


def test_auto_approver_is_refused_against_anything_but_localstack(tmp_path, make_responder):
    with pytest.raises(ValueError, match="only allowed against LocalStack"):
        make_responder(approver=AutoApprover(), endpoint="https://iam.amazonaws.com")
    with pytest.raises(ValueError):
        make_responder(approver=AutoApprover(), endpoint=None)
    make_responder(approver=AutoApprover(), endpoint="http://localhost:4566")     # fine
    make_responder(approver=AutoApprover(), endpoint=None, execute=False)         # dry run changes nothing, fine


def test_rollback_reactivates_the_deactivated_key(aws, make_responder, secret_finding):
    original = active_keys(aws)[0]["AccessKeyId"]
    r = make_responder()
    r.handle(secret_finding)
    short = Incident.from_asff(secret_finding).short
    steps = r.rollback(short)
    assert steps[0].ok and "re-activated" in steps[0].detail
    st = {k["AccessKeyId"]: k["Status"] for k in aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]}
    assert st[original] == "Active"
    with pytest.raises(KeyError):
        r.rollback("nosuchincident")


def test_bucket_flow_end_to_end(aws, make_responder, public_bucket_finding):
    from aegis_respond.playbooks.public_bucket import ALL_ON
    s3 = aws.get("s3")
    s3.create_bucket(Bucket="data-bucket")
    s3.put_public_access_block(Bucket="data-bucket", PublicAccessBlockConfiguration={k: False for k in ALL_ON})
    s3.put_bucket_acl(Bucket="data-bucket", ACL="public-read")
    out = make_responder().handle(public_bucket_finding)
    assert out.status == CONTAINED and out.playbook == "public_bucket"
    assert s3.get_public_access_block(Bucket="data-bucket")["PublicAccessBlockConfiguration"] == ALL_ON
