"""The triage cannot act, cannot reach the network except through one file, and does not know the lab (ADR-0013, ADR-0020)."""
import json
import re
import sys
from pathlib import Path

from tsupport import incident

ROOT = Path(__file__).resolve().parents[1]
SRC = sorted((ROOT / "aegis_triage").rglob("*.py")) + [ROOT / "triage.py", ROOT / "tools" / "evaluate.py"]
FORBIDDEN = ["cloudpurple", "unknown-laptop", "backdoor-", "999999999999", "555555555555", "run_id", "intern-policy", "purple-trail",
             "dev-svc", "data_bucket"]


def lib_sources():
    return [p for p in SRC if p.parent.name == "aegis_triage"]


def test_triage_has_no_aws_client_and_never_calls_plan_or_contain():
    for p in lib_sources():
        text = p.read_text()
        assert "boto3" not in text and "botocore" not in text, f"{p.name} talks to AWS"
        assert not re.search(r"\.(contain|rollback|verify)\(", text), f"{p.name} calls a playbook action"
        assert ".plan(" not in text, f"{p.name} asks a playbook for a plan"


def test_only_the_explainer_may_use_the_network_or_a_sdk():
    net = re.compile(r"\b(import|from)\s+(requests|urllib|http|socket|anthropic|httpx)\b")
    for p in lib_sources():
        if p.name != "explain.py":
            assert not net.search(p.read_text()), f"{p.name} imports a network library"


def test_the_decision_code_never_reads_model_output():
    """assess.py is where priority and action are decided. It must not import the explainer or see its text."""
    text = (ROOT / "aegis_triage" / "assess.py").read_text()
    assert "explain" not in text.replace("explainer", "") and "anthropic" not in text


def test_no_lab_names_or_scenario_ids_in_triage_code():
    for p in SRC:
        t = p.read_text()
        if p.name == "evaluate.py":
            continue                                   # the evaluation tool builds its own test events
        assert not [s for s in FORBIDDEN if s in t], p.name
        assert not re.search(r"\bS(0[1-9]|1[0-2])\b", t), p.name


def test_only_real_actions_can_come_out():
    from aegis_triage.note import ACTIONS
    from aegis_respond.playbooks import PLAYBOOKS
    assert set(ACTIONS) == {"contain_via_playbook", "escalate_to_human", "monitor"}
    from tsupport import run
    inc, _ = incident(req={"secretId": "prod/db"})
    note, _ = run(inc)
    assert note.playbook in PLAYBOOKS or note.playbook == ""


def test_advisor_works_inside_the_responder_and_leaves_the_plan_alone(tmp_path):
    from aegis_respond.clients import Clients
    from aegis_respond.playbooks import PLAYBOOKS
    from aegis_respond.policy import ResponsePolicy
    from aegis_triage.advisor import make_advisor
    from moto import mock_aws
    from rsupport import MOTO_ACCOUNT, Approve, AuditLog, Ledger, Recorder, Responder
    with mock_aws():
        c = Clients(MOTO_ACCOUNT)
        c.get("iam").create_user(UserName="dev-svc")
        c.get("iam").create_access_key(UserName="dev-svc")
        pol = ResponsePolicy.load()
        advisor = make_advisor(pol, PLAYBOOKS, env={})
        ap = Approve()
        r = Responder(policy=pol, approver=ap, notifier=Recorder(), audit=AuditLog(tmp_path / "a.jsonl"), ledger=Ledger(tmp_path / "l.json"),
                      execute=True, advisor=advisor)
        _, finding = incident(req={"secretId": "prod/db"})
        out = r.handle(finding)
        shown = ap.calls[0][1]
        planned = next(x for x in r.audit.records() if x["step"] == "plan")["data"]["summary"]
        assert out.status == "CONTAINED" and shown[:len(planned)] == planned
        extra = shown[len(planned):]
        assert extra and all(s.startswith("[triage") for s in extra)
        assert r.audit.verify()[0]


def test_cli_prints_the_note_and_changes_nothing(tmp_path, capsys, monkeypatch):
    import triage as cli
    _, finding = incident(req={"secretId": "prod/db"})
    f = tmp_path / "f.json"
    f.write_text(json.dumps(finding))
    monkeypatch.setattr(sys, "argv", ["triage.py", "note", str(f), "--scan", str(tmp_path / "none.json"), "--findings-dir", str(tmp_path)])
    assert cli.main() == 0
    out = capsys.readouterr().out
    assert "[triage, advisory only, words by template]" in out and "contain_via_playbook" not in out and "leaked_key" in out
    assert list(tmp_path.iterdir()) == [f]


def test_the_evaluation_tool_passes():
    from tools.evaluate import main
    assert main(write=False) == 0
