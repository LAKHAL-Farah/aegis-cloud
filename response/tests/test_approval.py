import threading
import time

import pytest
from aegis_respond.approval import (AutoApprover, FileApprover, TelegramAPI, TelegramApprover, sign_approval, verify_approval)
from aegis_respond.incident import Incident


@pytest.fixture
def inc(secret_finding):
    return Incident.from_asff(secret_finding)


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


def test_auto_approver_is_labelled_automated(inc):
    d = AutoApprover(delay_s=0).request(inc, ["x"], 10)
    assert d.approved and d.automated and "simulated" in d.reason


def test_file_approver_approve_deny_and_pending(tmp_path, inc):
    ap = FileApprover(tmp_path, poll_s=0.01)
    out = {}
    t = threading.Thread(target=lambda: out.update(d=ap.request(inc, ["do it"], 5)))
    t.start()
    for _ in range(200):
        if FileApprover.pending(tmp_path):
            break
        time.sleep(0.01)
    assert FileApprover.pending(tmp_path)[0]["plan"] == ["do it"]
    FileApprover.decide(tmp_path, inc.short, True, "farah")
    t.join(5)
    assert out["d"].approved and out["d"].by == "farah" and not FileApprover.pending(tmp_path)


def test_file_approver_deny(tmp_path, inc):
    ap = FileApprover(tmp_path, poll_s=0.01)
    out = {}
    t = threading.Thread(target=lambda: out.update(d=ap.request(inc, ["x"], 5)))
    t.start()
    while not FileApprover.pending(tmp_path):
        time.sleep(0.01)
    FileApprover.decide(tmp_path, inc.short, False, "farah")
    t.join(5)
    assert not out["d"].approved and out["d"].by == "farah"


def test_file_approver_times_out_closed(tmp_path, inc):
    c = Clock()
    d = FileApprover(tmp_path, poll_s=1, now=c.now, sleep=c.sleep).request(inc, ["x"], 30)
    assert not d.approved and d.by == "timeout" and d.waited_s >= 30
    assert not list(tmp_path.glob("*.request.json"))


def test_file_decision_needs_a_pending_request(tmp_path):
    with pytest.raises(FileNotFoundError):
        FileApprover.decide(tmp_path, "nope", True, "x")


def test_stale_decision_file_cannot_pre_approve(tmp_path, inc):
    (tmp_path / f"{inc.short}.decision").write_text("approve mallory")
    c = Clock()
    d = FileApprover(tmp_path, poll_s=1, now=c.now, sleep=c.sleep).request(inc, ["x"], 5)
    assert not d.approved                      # the leftover file was cleared before the request was published


# ---- Telegram
def approver(telegram, allowed=(1,), poll=1):
    return TelegramApprover(TelegramAPI("123:SECRET", telegram.base), chat_id=555, allowed_user_ids=list(allowed), poll_s=poll)


def tap_on_send(telegram, answer="y", **kw):
    def hook(body):
        data = body["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
        telegram.tap(data.rsplit(":", 1)[0] + f":{answer}", **kw)
    telegram.on_send = hook


def test_telegram_approve_by_allowed_user(telegram, inc):
    tap_on_send(telegram, "y", user_id=1, username="farah")
    d = approver(telegram).request(inc, ["Deactivate key"], 10)
    assert d.approved and d.by == "telegram:farah"
    msg = telegram.sent()[0]["text"]
    assert "Deactivate key" in msg and inc.title in msg
    assert any(m == "answerCallbackQuery" for m, _ in telegram.calls)
    assert any(m == "editMessageReplyMarkup" for m, _ in telegram.calls)     # buttons removed after the tap


def test_telegram_deny(telegram, inc):
    tap_on_send(telegram, "n")
    d = approver(telegram).request(inc, ["x"], 10)
    assert not d.approved and "denied" in d.reason


def test_telegram_ignores_strangers_then_times_out(telegram, inc):
    tap_on_send(telegram, "y", user_id=999)
    t0 = time.monotonic()
    d = approver(telegram, poll=1).request(inc, ["x"], 2)
    assert not d.approved and d.by == "timeout" and time.monotonic() - t0 < 6


def test_telegram_ignores_a_stale_button_from_an_earlier_request(telegram, inc):
    telegram.tap(f"aegis:{inc.short}:deadbeef:y", user_id=1)              # tapped before, for an old nonce
    d = approver(telegram, poll=1).request(inc, ["x"], 2)
    assert not d.approved and d.by == "timeout"


def test_telegram_needs_an_allow_list():
    with pytest.raises(ValueError):
        TelegramApprover(TelegramAPI("t"), 1, [])


def test_telegram_errors_never_leak_the_bot_token():
    api = TelegramAPI("123:TOPSECRET", "http://127.0.0.1:9")             # nothing listens there
    with pytest.raises(RuntimeError) as e:
        api.call("sendMessage", {}, timeout=1)
    assert "TOPSECRET" not in str(e.value) and "TOPSECRET" not in repr(e.value.__cause__)


# ---- signed approvals (Lambda path)
KEY = b"k" * 32


def good(incident="inc-1", by="farah", exp=2_000_000_000):
    return {"approved_by": by, "expires": exp, "signature": sign_approval(KEY, incident, by, exp)}


def test_signed_approval_verifies():
    assert verify_approval(KEY, "inc-1", good(), now=1.0).approved


@pytest.mark.parametrize("approval,why", [
    (None, "no approval"),
    ({"approved_by": "x"}, "malformed"),
    ({**good(), "signature": "0" * 64}, "does not match"),
    ({**good(by="farah"), "approved_by": "mallory"}, "does not match"),
    (good(exp=10), "expired"),
])
def test_bad_approvals_are_refused(approval, why):
    d = verify_approval(KEY, "inc-1", approval, now=100.0)
    assert not d.approved and why in d.reason


def test_an_approval_for_one_incident_does_not_approve_another():
    assert not verify_approval(KEY, "inc-2", good("inc-1"), now=1.0).approved


def test_no_key_means_no_approval():
    assert not verify_approval(b"", "inc-1", good(), now=1.0).approved


def test_pending_never_trips_over_a_half_written_or_vanishing_request(tmp_path):
    (tmp_path / "a.request.json").write_text("")                # what a reader saw mid-write before the atomic rename
    (tmp_path / "b.request.json").write_text('{"incident_id": "b", "plan": []}')
    assert [p["incident_id"] for p in FileApprover.pending(tmp_path)] == ["b"]
