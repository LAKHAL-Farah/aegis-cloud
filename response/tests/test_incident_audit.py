import json

import pytest
from aegis_respond.audit import AuditLog, scrub
from aegis_respond.incident import Incident
from rsupport import MOTO_ACCOUNT


def test_incident_is_read_from_a_real_engine_finding(secret_finding):
    inc = Incident.from_asff(secret_finding)
    assert inc.rule == "AEG-CRED-001" and inc.technique == "T1555.006" and inc.severity == "medium"
    assert inc.principal == f"arn:aws:iam::{MOTO_ACCOUNT}:user/dev-svc" and inc.identity == "dev-svc"
    assert inc.access_key_id == "AKIAEXAMPLEKEY0001" and inc.account_id == MOTO_ACCOUNT
    assert (inc.detected_at - inc.event_time).total_seconds() == 2.0
    assert len(inc.short) == 12 and inc.short == Incident.from_asff(secret_finding).short


def test_public_view_never_carries_key_material(secret_finding):
    pub = Incident.from_asff(secret_finding).public()
    assert "AKIA" not in json.dumps(pub)


@pytest.mark.parametrize("bad", [{}, {"Id": "x"}, {"Id": "x", "GeneratorId": "guardduty/x/y", "AwsAccountId": "1", "Types": ["a/b/c"],
                                                  "Severity": {"Label": "HIGH"}, "Title": "t", "Resources": [{}], "CreatedAt": "2026-01-01T00:00:00Z"}])
def test_foreign_or_partial_findings_are_rejected(bad):
    with pytest.raises(ValueError):
        Incident.from_asff(bad)


def test_audit_chain_verifies_and_detects_edits(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(4):
        log.append("inc1", f"step{i}", "ok", n=i)
    assert log.verify() == (True, "4 records, chain intact")
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    # edit a value
    tampered = json.loads(lines[1])
    tampered["data"]["n"] = 99
    (tmp_path / "b.jsonl").write_text("\n".join([lines[0], json.dumps(tampered, sort_keys=True), *lines[2:]]) + "\n")
    assert AuditLog(tmp_path / "b.jsonl").verify()[0] is False
    # remove a line
    (tmp_path / "c.jsonl").write_text("\n".join([lines[0], *lines[2:]]) + "\n")
    assert AuditLog(tmp_path / "c.jsonl").verify() == (False, "chain broken at seq 3")
    # reorder
    (tmp_path / "d.jsonl").write_text("\n".join([lines[1], lines[0], *lines[2:]]) + "\n")
    assert AuditLog(tmp_path / "d.jsonl").verify()[0] is False


def test_audit_scrubs_secrets_and_mirrors(tmp_path):
    seen = []
    log = AuditLog(tmp_path / "a.jsonl", mirror=seen.append)
    log.append("i", "rotate", "ok", SecretAccessKey="wJalr", nested={"api_token": "t0k", "ok": 1})
    text = (tmp_path / "a.jsonl").read_text()
    assert "wJalr" not in text and "t0k" not in text and '"ok": 1' in text
    assert len(seen) == 1 and "wJalr" not in seen[0]
    assert scrub({"Authorization": "Bearer x"}) == {"Authorization": "[redacted]"}


def test_audit_survives_a_restart(tmp_path):
    AuditLog(tmp_path / "a.jsonl").append("i", "s", "ok")
    log2 = AuditLog(tmp_path / "a.jsonl")
    assert log2.append("i", "t", "ok")["seq"] == 2 and log2.verify()[0]
