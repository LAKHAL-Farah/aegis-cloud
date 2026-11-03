"""Every technique the attack catalogue exercises has at least one rule. Rules are written from the
`expected_detection` text, then proven by re-running the unmodified range (make stage3-run)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cloudpurple"))

from attacks import scenarios  # noqa: F401,E402
from attacks.scenario import all_scenarios  # noqa: E402
from aegis_detect.rules import all_rules  # noqa: E402


def test_every_scenario_technique_has_a_rule():
    covered = {r.technique for r in all_rules()}
    missing = {s.id: s.technique for s in all_scenarios() if s.technique not in covered}
    assert not missing, f"no rule for: {missing}"


def test_rule_ids_are_unique_and_mapped():
    rules = all_rules()
    assert len({r.id for r in rules}) == len(rules)
    assert all(r.technique.startswith("T") and r.tactic for r in rules)