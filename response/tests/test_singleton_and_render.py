"""Two executing responders on one state directory broke the audit chain (2026-11-08). One must refuse to start.
Advice is shown under its own heading, never as a plan step."""
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from aegis_respond import advice, singleton

ROOT = Path(__file__).resolve().parents[1]


def test_second_holder_is_refused_and_a_released_lock_can_be_taken(tmp_path):
    first, _ = singleton.acquire("responder", tmp_path)
    assert first is not None
    second, holder = singleton.acquire("responder", tmp_path)
    assert second is None and holder == str(os.getpid())
    first.close()                                           # what happens when the holder dies, however it dies
    third, _ = singleton.acquire("responder", tmp_path)
    assert third is not None
    third.close()


def test_different_state_directories_do_not_block_each_other(tmp_path):
    a, _ = singleton.acquire("responder", tmp_path / "a")
    b, _ = singleton.acquire("responder", tmp_path / "b")
    assert a is not None and b is not None
    a.close(); b.close()


def holder_process(state, seconds):
    code = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(ROOT)!r})
        from aegis_respond import singleton
        h, _ = singleton.acquire("responder", {str(state)!r})
        print("held" if h else "refused", flush=True)
        time.sleep({seconds})
    """)
    p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "held"
    return p


def test_a_second_executing_responder_process_refuses_to_start(tmp_path):
    holder = holder_process(tmp_path, 30)
    try:
        r = subprocess.run([sys.executable, str(ROOT / "respond.py"), "--state-dir", str(tmp_path), "--endpoint", "http://127.0.0.1:1",
                            "watch", "--execute", "--approver", "file", "--findings-dir", str(tmp_path / "f")],
                           capture_output=True, text=True, timeout=30, env={**os.environ, "AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t"})
        assert r.returncode == 1 and "already holds" in r.stderr and str(holder.pid) in r.stderr
    finally:
        holder.kill()


def test_the_lock_dies_with_its_holder(tmp_path):
    holder = holder_process(tmp_path, 30)
    holder.kill()
    holder.wait()
    time.sleep(0.2)
    h, _ = singleton.acquire("responder", tmp_path)
    assert h is not None
    h.close()


def test_a_dry_run_watcher_does_not_need_the_lock(tmp_path):
    """Only an executing responder acts, so only it is exclusive. A planning-only one may run beside it."""
    holder = holder_process(tmp_path, 30)
    try:
        r = subprocess.Popen([sys.executable, str(ROOT / "respond.py"), "--state-dir", str(tmp_path), "--endpoint", "http://127.0.0.1:1",
                              "watch", "--findings-dir", str(tmp_path / "f")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                             env={**os.environ, "AWS_ACCESS_KEY_ID": "t", "AWS_SECRET_ACCESS_KEY": "t"})
        time.sleep(2)
        assert r.poll() is None, r.stderr.read()            # still running
        r.kill()
    finally:
        holder.kill()


# ---- advice rendering
def test_advice_lines_are_always_tagged_and_split_off_the_plan():
    assert advice.tag("looks serious") == "[advice] looks serious" and advice.tag("[triage] x") == "[triage] x"
    plan, adv = advice.split(["Deactivate key", "[triage] a", "[advice] b"])
    assert plan == ["Deactivate key"] and adv == ["[triage] a", "[advice] b"]


def test_plan_steps_never_start_with_a_bracket(aws_for_plans):
    """The split relies on it. Checked on the plans the real playbooks produce."""
    assert aws_for_plans and all(not s.startswith("[") for s in aws_for_plans)


@pytest.fixture
def aws_for_plans(make_responder, secret_finding):
    from aegis_respond.clients import Clients
    from moto import mock_aws
    from rsupport import MOTO_ACCOUNT
    with mock_aws():
        c = Clients(MOTO_ACCOUNT)
        c.get("iam").create_user(UserName="dev-svc")
        c.get("iam").create_access_key(UserName="dev-svc")
        r = make_responder(execute=False)
        r.handle(secret_finding)
        yield next(x for x in r.audit.records() if x["step"] == "plan")["data"]["summary"]


def test_prompt_shows_advice_under_its_own_heading_not_as_a_plan_step(tmp_path, capsys):
    import respond
    (tmp_path / "approvals").mkdir()
    (tmp_path / "approvals" / "abc.request.json").write_text(json.dumps({
        "incident_id": "abc", "severity": "medium", "title": "Secret read",
        "plan": ["Deactivate access key ...X of IAM user u", "[triage, advisory only, words by template] P3: x", "[triage] proposal: y"]}))
    respond.prompt_loop(tmp_path, once=True, who="t", input_fn=lambda _: "n", sleep=lambda s: None)
    out = capsys.readouterr().out
    assert "  - Deactivate access key" in out and advice.HEADER in out
    assert "- [triage" not in out and "  [triage, advisory only" in out
    assert out.index("Deactivate") < out.index(advice.HEADER) < out.index("[triage, advisory")

