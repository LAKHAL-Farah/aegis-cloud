import json
import sys
from pathlib import Path

import pytest
from twins import ACCT, collect_twin

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "detections"))
sys.path.insert(0, str(ROOT / "response"))

import sentinel as cli  # noqa: E402
from aegis_sentinel import cypher, findings, snapshot  # noqa: E402
from aegis_sentinel.escalation import scan  # noqa: E402


@pytest.fixture
def snaps(tmp_path):
    out = {}
    for name, hardened in (("purple", False), ("hardened", True)):
        out[name] = tmp_path / f"{name}.json"
        snapshot.save(collect_twin(hardened), out[name])
    return out


def run(argv, monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "OUT", tmp_path / "out")
    monkeypatch.setattr(sys, "argv", ["sentinel.py", *argv])
    return cli.main()


def test_scan_prints_the_path_and_writes_scan_json_and_findings(snaps, monkeypatch, tmp_path, capsys):
    code = run(["scan", str(snaps["purple"]), "--write"], monkeypatch, tmp_path)
    out = capsys.readouterr().out
    assert code == 0 and "ESC-01" in out and "intern" in out and "dev-svc" in out
    merged = json.loads((tmp_path / "out" / "scan.json").read_text())
    assert merged["schema"] == "aegis.sentinel-scan/v1" and ACCT in merged["accounts"]
    assert len(list((tmp_path / "out" / "findings").glob("*.json"))) == 2


def test_fail_on_path_is_a_ci_gate(snaps, monkeypatch, tmp_path):
    assert run(["scan", str(snaps["purple"]), "--fail-on-path"], monkeypatch, tmp_path) == 1
    assert run(["scan", str(snaps["hardened"]), "--fail-on-path"], monkeypatch, tmp_path) == 0


def test_findings_are_valid_asff_and_not_mistaken_for_incidents(snaps):
    from aegis_detect.asff import REQUIRED
    fs = findings.to_asff(scan(snapshot.load(snaps["purple"])))
    assert {f["GeneratorId"] for f in fs} == {"aegiscloud/sentinel/AEG-IAM-001", "aegiscloud/sentinel/AEG-IAM-002"}
    for f in fs:
        assert all(k in f for k in REQUIRED) and f["ProductFields"]["aegis/kind"] == "posture"
    from aegis_respond.incident import Incident
    from aegis_respond.policy import ResponsePolicy
    from aegis_respond.playbooks import PLAYBOOKS
    pol = ResponsePolicy.load()
    for f in fs:                                      # even if one were fed to the responder, no playbook would claim it
        inc = Incident.from_asff(f)
        assert not any(p.matches(inc, pol) for p in PLAYBOOKS.values())


def test_leastpriv_cli_writes_a_policy_with_its_checks(snaps, monkeypatch, tmp_path, capsys):
    from test_leastpriv import Small                  # a tiny action list: the real one takes seconds to load
    monkeypatch.setattr(cli, "Universe", Small)
    trail = tmp_path / "trail.json"
    trail.write_text(json.dumps({"Records": [{
        "eventTime": "t", "eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCT}:user/intern", "accountId": ACCT}}]}))
    code = run(["leastpriv", "--snapshot", str(snaps["purple"]), "--trail", str(trail), "--principal", "intern"], monkeypatch, tmp_path)
    out = capsys.readouterr().out
    assert code == 0 and "escalation: escalates -> ordinary" in out and "coverage of observed calls: complete" in out
    assert json.loads((tmp_path / "out" / "leastpriv-intern.json").read_text())["policy"]["Statement"]


def test_cypher_is_text_only_and_describes_the_edges(snaps):
    text = cypher.export(snapshot.load(snaps["purple"]))
    assert "ESC-01" in text and "MERGE" in text and "http" not in text


def test_scp_denies_are_applied_to_everyone(snaps, monkeypatch, tmp_path, capsys):
    scp = tmp_path / "scp.json"
    scp.write_text(json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Deny", "Action": ["iam:CreatePolicyVersion"], "Resource": "*"}]}))
    run(["scan", str(snaps["purple"]), "--scp", str(scp)], monkeypatch, tmp_path)
    out = capsys.readouterr().out
    assert "ESC-01" not in out                        # the account-wide deny closes the intern's only route


def test_fetch_trail_parses_the_record_json_and_skips_garbage():
    events = [{"CloudTrailEvent": json.dumps({"eventName": "A"})}, {"CloudTrailEvent": "not json"}, {"Other": 1}]

    class CT:
        def get_paginator(self, _):
            class P:
                def paginate(self, **kw):
                    return [{"Events": events}]
            return P()

    assert cli.fetch_trail(CT()) == [{"eventName": "A"}]


def test_collect_reports_an_unreachable_endpoint_instead_of_a_traceback(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "111111111111")
    code = run(["collect", "--endpoint", "http://127.0.0.1:1", "--account", "111111111111", "--out", str(tmp_path / "s.json")], monkeypatch, tmp_path)
    assert code == 1 and "could not collect" in capsys.readouterr().err and not (tmp_path / "s.json").exists()


def test_leastpriv_explains_an_empty_result(snaps, monkeypatch, tmp_path, capsys):
    trail = tmp_path / "t.json"
    trail.write_text(json.dumps({"Records": [{"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "userIdentity": {"type": "Root"}},
                                             {"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "userIdentity": {}}]}))
    code = run(["leastpriv", "--snapshot", str(snaps["purple"]), "--trail", str(trail), "--principal", "dev-svc"], monkeypatch, tmp_path)
    err = capsys.readouterr().err
    assert code == 1 and "2 events" in err and "Root (no arn): 1" in err and "no type (no arn): 1" in err and "make attack" in err
