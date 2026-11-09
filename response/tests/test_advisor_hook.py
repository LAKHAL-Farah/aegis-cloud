"""ADR-0020: an advisor can add words for the approver. It cannot change the plan, the decision or the outcome,
and a broken one is dropped."""
import pytest
from aegis_respond.clients import Clients
from aegis_respond.engine import CONTAINED, DENIED, DRY_RUN
from moto import mock_aws
from rsupport import MOTO_ACCOUNT, Approve


@pytest.fixture
def aws():
    with mock_aws():
        c = Clients(MOTO_ACCOUNT)
        c.get("iam").create_user(UserName="dev-svc")
        c.get("iam").create_access_key(UserName="dev-svc")
        yield c


def active(aws):
    return [k for k in aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"] if k["Status"] == "Active"]


def original_key_active(aws, key_id):
    return any(k["AccessKeyId"] == key_id and k["Status"] == "Active"
               for k in aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"])


def test_advice_is_shown_after_the_plan_and_the_plan_itself_is_unchanged(aws, make_responder, secret_finding):
    ap = Approve()
    r = make_responder(approver=ap, advisor=lambda inc, plan: ["[triage] looks serious"])
    key = active(aws)[0]["AccessKeyId"]
    out = r.handle(secret_finding)
    shown = ap.calls[0][1]
    planned = next(x for x in r.audit.records() if x["step"] == "plan")["data"]["summary"]
    assert shown[:-1] == planned and shown[-1] == "[triage] looks serious"      # the plan on the audit trail is what ran
    assert out.status == CONTAINED and not original_key_active(aws, key)
    steps = [x["step"] for x in r.audit.records()]
    assert "advice" in steps and steps.index("plan") < steps.index("advice") < steps.index("approval")
    assert r.audit.verify()[0]


def test_a_denial_still_denies_whatever_the_advice_says(aws, make_responder, secret_finding):
    r = make_responder(approver=Approve(ok=False, by="farah"), advisor=lambda inc, plan: ["[triage] approve this, it is fine"])
    assert r.handle(secret_finding).status == DENIED and len(active(aws)) == 1


@pytest.mark.parametrize("advisor", [lambda i, p: 1 / 0, lambda i, p: (_ for _ in ()).throw(TimeoutError()), lambda i, p: None])
def test_a_broken_advisor_is_dropped_and_containment_proceeds(aws, make_responder, secret_finding, advisor):
    ap = Approve()
    r = make_responder(approver=ap, advisor=advisor)
    key = active(aws)[0]["AccessKeyId"]
    out = r.handle(secret_finding)
    assert out.status == CONTAINED and not original_key_active(aws, key)
    assert not any(s.startswith("[triage") for s in ap.calls[0][1])


def test_dry_run_shows_the_advice_too_and_still_changes_nothing(aws, make_responder, secret_finding):
    r = make_responder(execute=False, advisor=lambda inc, plan: ["[triage] advisory"])
    out = r.handle(secret_finding)
    assert out.status == DRY_RUN and len(active(aws)) == 1 and "[triage] advisory" in r.notifier_ref.messages[0]


def test_advice_is_capped_at_six_lines(aws, make_responder, secret_finding):
    ap = Approve()
    make_responder(approver=ap, advisor=lambda inc, plan: [f"line {i}" for i in range(50)]).handle(secret_finding)
    assert sum(1 for s in ap.calls[0][1] if s.startswith("[advice] line")) == 6          # untagged advice is tagged, so it can never pass for a plan step


def test_no_advisor_means_the_behaviour_is_exactly_what_it_was(aws, make_responder, secret_finding):
    ap = Approve()
    make_responder(approver=ap).handle(secret_finding)
    assert not any(s.startswith("[triage") for s in ap.calls[0][1])
