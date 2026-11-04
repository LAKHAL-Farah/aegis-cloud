"""ADR-0013 applies to the responder too: it must react to the finding, never to the test harness."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ["cloudpurple", "unknown-laptop", "backdoor-", "999999999999", "555555555555", "run_id", "intern-policy",
             "purple-trail", "dev-svc", "data_bucket", "attacker"]


def sources():
    return list((ROOT / "aegis_respond").rglob("*.py")) + [ROOT / "policy.json", ROOT / "respond.py"]


def test_no_harness_strings_in_response_code():
    hits = [(p.name, s) for p in sources() for s in FORBIDDEN if s in p.read_text()]
    assert not hits, f"response code references the range harness: {hits}"


def test_no_scenario_ids_in_response_code():
    pat = re.compile(r"\bS(0[1-9]|1[0-2])\b")
    hits = [(p.name, m.group()) for p in sources() for m in pat.finditer(p.read_text())]
    assert not hits, f"response code mentions scenario ids: {hits}"


def test_every_rule_in_the_policy_exists_in_the_detection_engine():
    import json
    from aegis_detect import rules  # noqa: F401  (registers everything)
    from aegis_detect.rules.base import REGISTRY
    policy = json.loads((ROOT / "policy.json").read_text())
    for pid, cfg in policy["playbooks"].items():
        for rule in cfg.get("rules", []):
            assert rule in REGISTRY, f"{pid} listens for {rule}, which the engine does not have"


def test_every_playbook_in_the_policy_exists():
    import json
    from aegis_respond.playbooks import PLAYBOOKS
    assert set(json.loads((ROOT / "policy.json").read_text())["playbooks"]) <= set(PLAYBOOKS)
