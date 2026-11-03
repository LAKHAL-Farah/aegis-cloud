"""Static checks of the SIEM files. None of this needs Docker."""
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "siem"))

import index_scorecard  # noqa: E402
from wazuh_bridge import convert  # noqa: E402

RULES = ROOT / "siem" / "wazuh" / "local_rules.xml"


def rules():
    return ET.parse(RULES).getroot().findall(".//rule")


def test_wazuh_rules_are_well_formed_xml_with_unique_ids_in_our_range():
    ids = [int(r.get("id")) for r in rules()]
    assert ids and len(ids) == len(set(ids))
    assert all(100100 <= i <= 100299 for i in ids)


def test_every_alerting_rule_carries_a_mitre_technique():
    for r in rules():
        if int(r.get("level")) > 0:
            assert r.find("mitre/id") is not None, f"rule {r.get('id')} has no MITRE id"


def test_children_point_at_existing_parents():
    ids = {r.get("id") for r in rules()}
    for r in rules():
        for tag in ("if_sid", "if_matched_sid"):
            for el in r.findall(tag):
                assert el.text in ids, f"rule {r.get('id')} references missing {el.text}"


def test_wazuh_samples_and_expectations_line_up():
    samples = (ROOT / "siem/wazuh/tests/samples.jsonl").read_text().strip().splitlines()
    expected = (ROOT / "siem/wazuh/tests/expected.txt").read_text().split()
    assert len(samples) == len(expected)
    for line in samples:
        json.loads(line)
    known = {r.get("id") for r in rules()} | {"NONE"}
    assert set(expected) <= known


def test_bridge_converts_a_wazuh_alert_to_the_contract():
    wazuh = {"rule": {"id": "100110", "level": 14, "description": "AegisCloud: CloudTrail logging stopped",
                      "mitre": {"id": ["T1562.008"]}},
             "data": {"aegis_account_id": "555555555555", "eventTime": "2026-10-31T12:00:01Z", "eventID": "e1"}}
    now = datetime(2026, 10, 31, 12, 0, 3, tzinfo=timezone.utc)
    a = convert(json.dumps(wazuh), now)
    assert a["technique"] == "T1562.008" and a["account_id"] == "555555555555" and a["source"] == "wazuh"
    assert a["event_time"] == "2026-10-31T12:00:01Z" and a["detected_at"].startswith("2026-10-31T12:00:03")
    assert a["severity"] == "high"


def test_bridge_ignores_other_rules_and_garbage():
    assert convert("not json") is None
    assert convert(json.dumps({"rule": {"id": "5710", "mitre": {"id": ["T1110"]}}, "data": {}})) is None
    assert convert(json.dumps({"rule": {"id": "100110", "mitre": {"id": ["T1562.008"]}}, "data": {}})) is None


def test_scorecard_bulk_lines_are_paired_action_and_document():
    card = {"generated": "2026-10-31 15:37 UTC", "rows": [
        {"id": "S01", "technique": "T1580", "tactic": "Discovery", "verdict": "NEITHER", "detected": False,
         "purple": {"telemetry": "FULL"}}]}
    lines = index_scorecard.bulk_lines("baseline", card)
    assert len(lines) == 2
    doc = json.loads(lines[1])
    assert doc["label"] == "baseline" and doc["telemetry"] == "FULL" and doc["attack_start"].endswith("Z")


def test_compose_has_the_services_and_heap_cap():
    text = (ROOT / "docker-compose.siem.yml").read_text()
    for needle in ("opensearch:", "dashboards:", "wazuh:", "-Xmx512m", "DISABLE_SECURITY_PLUGIN=true", '127.0.0.1:9200:9200'):
        assert needle in text


def test_falco_bridge_needs_the_aegis_tag_and_a_technique():
    import falco_bridge
    ok = {"rule": "Aegis shell in container", "priority": "Warning", "time": "2026-10-31T12:00:00Z",
          "tags": ["aegis", "container", "T1609"], "output": "Shell in container"}
    a = falco_bridge.convert(json.dumps(ok), "555555555555")
    assert a["technique"] == "T1609" and a["source"] == "falco" and a["severity"] == "medium"
    assert falco_bridge.convert(json.dumps({**ok, "tags": ["container", "T1609"]}), "555555555555") is None
    assert falco_bridge.convert(json.dumps({**ok, "tags": ["aegis"]}), "555555555555") is None
    assert falco_bridge.convert("garbage", "555555555555") is None

def test_bridge_takes_the_technique_from_our_rules_even_when_wazuh_has_no_mitre_block():
    wazuh = {"rule": {"id": "100180", "level": 8, "description": "AegisCloud: secret value read"},
             "data": {"aegis_account_id": "555555555555", "eventTime": "2026-11-03T20:53:34.561Z"}}
    assert convert(json.dumps(wazuh))["technique"] == "T1555.006"


def test_every_alerting_rule_has_a_technique_in_the_bridge_table():
    import wazuh_bridge
    for r in rules():
        if int(r.get("level")) > 0:
            assert r.get("id") in wazuh_bridge.TECHNIQUES
