import threading
import time

import pytest
from aegis_respond.approval import AutoApprover, FileApprover, SlackAPI, SlackApprover, sign_approval, verify_approval
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


# ---- Slack (reactions, polled outward: no public URL)
ALLOWED = ["U0FARAH"]


def approver(slack, allowed=tuple(ALLOWED), poll=0.02):
    return SlackApprover(SlackAPI("xoxb-SECRET-TOKEN", slack.base), "C0TEST", list(allowed), poll_s=poll)


def react_on_post(slack, name, users):
    slack.on_post = lambda ts: slack.react(name, users, ts)


def test_slack_approve_by_an_allowed_user(slack, inc):
    react_on_post(slack, "white_check_mark", ["U0FARAH"])
    d = approver(slack).request(inc, ["Deactivate key"], 5)
    assert d.approved and d.by == "slack:U0FARAH" and not d.automated
    text = slack.messages[0]["text"]
    assert "Deactivate key" in text and inc.title in text and "<@U0FARAH>" in text and ":white_check_mark:" in text
    assert "Approved by <@U0FARAH>" in slack.replies[0]["text"] and slack.replies[0]["thread_ts"] == slack.messages[0]["ts"]


def test_slack_deny_by_an_allowed_user(slack, inc):
    react_on_post(slack, "x", ["U0FARAH"])
    d = approver(slack).request(inc, ["x"], 5)
    assert not d.approved and d.by == "slack:U0FARAH" and "denied" in d.reason


def test_slack_deny_beats_approve(slack, inc):
    def both(ts):
        slack.react("white_check_mark", ["U0FARAH"], ts)
        slack.react("x", ["U0FARAH"], ts)
    slack.on_post = both
    assert not approver(slack).request(inc, ["x"], 5).approved


def test_slack_ignores_reactions_from_people_who_are_not_allowed(slack, inc):
    react_on_post(slack, "white_check_mark", ["U0STRANGER"])
    d = approver(slack).request(inc, ["x"], 0.4)
    assert not d.approved and d.by == "timeout" and "No decision" in slack.replies[0]["text"]


def test_slack_ignores_a_reaction_on_some_other_message(slack, inc):
    slack.messages.append({"ts": "0.1", "text": "an older approval", "reactions": []})
    slack.react("white_check_mark", ["U0FARAH"], "0.1")                       # approving yesterday's message
    assert not approver(slack).request(inc, ["x"], 0.4).approved


def test_slack_handles_skin_tone_suffixes_and_unrelated_emoji(slack, inc):
    def reacts(ts):
        slack.react("eyes", ["U0FARAH"], ts)
        slack.react("white_check_mark::skin-tone-3", ["U0FARAH"], ts)
    slack.on_post = reacts
    assert approver(slack).request(inc, ["x"], 5).approved


def test_slack_survives_a_rate_limit_while_polling(slack, inc):
    slack.fail_reactions = 2
    react_on_post(slack, "white_check_mark", ["U0FARAH"])
    assert approver(slack).request(inc, ["x"], 5).approved


def test_slack_refusal_on_post_raises_so_the_engine_denies(slack, inc):
    slack.refuse = "channel_not_found"
    with pytest.raises(RuntimeError, match="channel_not_found"):
        approver(slack).request(inc, ["x"], 1)


def test_slack_needs_an_allow_list():
    with pytest.raises(ValueError):
        SlackApprover(SlackAPI("t"), "C1", [])
    with pytest.raises(ValueError):
        SlackApprover(SlackAPI("t"), "C1", ["", "  "])


def test_slack_token_is_sent_as_a_header_and_never_leaks(slack, inc):
    react_on_post(slack, "white_check_mark", ["U0FARAH"])
    api = SlackAPI("xoxb-SECRET-TOKEN", slack.base)
    approver(slack).request(inc, ["x"], 5)
    assert set(slack.auth) == {"Bearer xoxb-SECRET-TOKEN"}
    assert "xoxb-SECRET" not in repr(api) and all("xoxb" not in str(f) for _, f in slack.calls)
    dead = SlackAPI("xoxb-SECRET-TOKEN", "http://127.0.0.1:9")               # nothing listens there
    with pytest.raises(RuntimeError) as e:
        dead.call("chat.postMessage", {}, timeout=1)
    assert "xoxb" not in str(e.value) and "xoxb" not in repr(e.value.__cause__)


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


def test_slack_shows_advice_under_its_own_heading_and_the_plan_stays_a_plan(slack, inc):
    react_on_post(slack, "white_check_mark", ["U0FARAH"])
    approver(slack).request(inc, ["Deactivate key", "[triage, advisory only, words by template] P3: x"], 5)
    text = slack.messages[0]["text"]
    planned, _, advice_part = text.partition("*Advice (not part of the plan")
    assert "- Deactivate key" in planned and "[triage" not in planned
    assert "[triage, advisory only" in advice_part and "- [triage" not in text


def test_slack_without_advice_is_unchanged(slack, inc):
    react_on_post(slack, "white_check_mark", ["U0FARAH"])
    approver(slack).request(inc, ["Deactivate key"], 5)
    assert "Advice" not in slack.messages[0]["text"]
