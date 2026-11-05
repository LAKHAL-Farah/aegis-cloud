"""Stage 5: a responder that dies mid-approval, or is down when a finding arrives, still owes the response."""
import json
import threading
import time

import pytest
from aegis_respond.clients import Clients
from aegis_respond.engine import CONTAINED
from aegis_respond.heartbeat import Heartbeat
from aegis_respond.incident import Incident
from aegis_respond.recovery import backlog, classify
from aegis_respond.watch import watch
from moto import mock_aws
from rsupport import MOTO_ACCOUNT, Approve, cloudtrail, findings_for


@pytest.fixture
def aws():
    with mock_aws():
        c = Clients(MOTO_ACCOUNT)
        c.get("iam").create_user(UserName="dev-svc")
        c.get("iam").create_access_key(UserName="dev-svc")
        yield c


def active(aws):
    return [k for k in aws.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"] if k["Status"] == "Active"]


def contained(aws, original):
    """The leaked key is no longer active (containment may also mint a replacement, so do not count keys)."""
    return original not in {k["AccessKeyId"] for k in active(aws)}


class Killed(Exception):
    pass


class DiesWhileAsking:
    name = "dies"

    def request(self, inc, plan, timeout_s):
        raise KeyboardInterrupt        # not an Exception: models SIGKILL/Ctrl-C reaching the thread, passes `except Exception`


def drop(dirpath, finding, name="f.json"):
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / name).write_text(json.dumps(finding))


def run(resp, findings, **kw):
    stop = threading.Event()
    t = threading.Thread(target=watch, args=(resp, findings, stop), kwargs={"poll_s": 0.02, **kw})
    t.start()
    time.sleep(0.4)
    stop.set()
    t.join(5)


def test_the_gap_exists_without_resume(aws, make_responder, secret_finding, tmp_path):
    """Regression marker for the Stage 4 behaviour: a finding written while the responder was down is never handled."""
    drop(tmp_path / "findings", secret_finding)
    resp = make_responder(approver=Approve())
    run(resp, tmp_path / "findings")                       # starts after the file exists: ignored
    assert len(active(aws)) == 1


def test_resume_handles_a_finding_that_arrived_while_down(aws, make_responder, secret_finding, tmp_path):
    original = active(aws)[0]["AccessKeyId"]
    drop(tmp_path / "findings", secret_finding)
    resp = make_responder(approver=Approve())
    run(resp, tmp_path / "findings", resume=True)
    assert contained(aws, original)


def test_resume_asks_again_after_a_kill_in_the_middle_of_approval(aws, make_responder, secret_finding, tmp_path):
    original = active(aws)[0]["AccessKeyId"]
    # run 1: the responder claims the incident, then dies while the person is deciding
    r1 = make_responder(approver=DiesWhileAsking())
    with pytest.raises(KeyboardInterrupt):
        r1.handle(secret_finding)
    closed, interrupted = classify(r1.audit)
    inc = Incident.from_asff(secret_finding)
    assert inc.short in interrupted and not closed
    assert len(active(aws)) == 1                           # nothing changed without approval

    # run 2: without recovery the claim makes it a DUPLICATE and the incident is silently lost
    assert r1.handle(secret_finding).status == "DUPLICATE"

    # with recovery: the claim is released, the person is asked again, the key is contained
    drop(tmp_path / "findings", secret_finding)
    ask = Approve()
    r2 = make_responder(approver=ask)
    r2.ledger, r2.audit = r1.ledger, r1.audit
    assert [p.name for p in backlog(r2, tmp_path / "findings")] == ["f.json"]
    out = r2.handle(secret_finding)
    assert out.status == CONTAINED and len(ask.calls) == 1 and contained(aws, original)
    assert any(r["step"] == "resumed" for r in r1.audit.records(inc.short))


def test_resume_does_not_repeat_closed_incidents(aws, make_responder, secret_finding, tmp_path):
    r = make_responder(approver=Approve())
    assert r.handle(secret_finding).status == CONTAINED
    drop(tmp_path / "findings", secret_finding)
    assert backlog(r, tmp_path / "findings") == []


def test_release_removes_only_its_own_cooldown(make_responder, tmp_path):
    r = make_responder()
    assert r.ledger.claim("a", "pb|alice", 100.0, 60) is None
    assert r.ledger.claim("b", "pb|bob", 101.0, 60) is None
    assert r.ledger.release("a") is True
    assert r.ledger.claim("a2", "pb|alice", 102.0, 60) is None      # alice's cooldown is gone
    assert "bob" in (r.ledger.claim("b2", "pb|bob", 102.0, 60) or "")  # bob's is intact
    assert r.ledger.release("missing") is False


def test_unreadable_files_are_not_in_the_backlog(make_responder, tmp_path):
    d = tmp_path / "findings"
    d.mkdir()
    (d / "junk.json").write_text("{nope")
    assert backlog(make_responder(), d) == []


def test_on_tick_runs_every_loop_and_heartbeat_follows_the_contract(tmp_path, make_responder):
    hb = Heartbeat(tmp_path / "hb.json", "responder")
    (tmp_path / "findings").mkdir()
    run(make_responder(), tmp_path / "findings", on_tick=hb.beat)
    data = json.loads((tmp_path / "hb.json").read_text())
    assert data["component"] == "responder" and data["seq"] > 3


def test_old_findings_are_not_chased(make_responder, secret_finding, tmp_path):
    d = tmp_path / "findings"
    drop(d, secret_finding)
    r = make_responder(clock=lambda: Incident.from_asff(secret_finding).detected_at.timestamp() + 4000)
    assert backlog(r, d, max_age_s=900) == []
    assert [p.name for p in backlog(r, d, max_age_s=9000)] == ["f.json"]
