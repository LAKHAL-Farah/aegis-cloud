"""Detectors must catch the technique, not the test (docs/STAGE3.md section 1.3).
These strings identify the range's own harness. None of them may appear in detection code or policy."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ["cloudpurple", "unknown-laptop", "backdoor-", "999999999999", "555555555555", "run_id",
             "intern-policy", "purple-trail", "customers/record"]


def sources():
    for p in list((ROOT / "aegis_detect").rglob("*.py")) + [ROOT / "policy.json"]:
        yield p


def test_no_harness_strings_in_detection_code():
    hits = [(p.name, s) for p in sources() for s in FORBIDDEN if s in p.read_text()]
    assert not hits, f"detection code references the range harness: {hits}"


def test_no_scenario_ids_in_detection_code():
    import re
    pat = re.compile(r"\bS(0[1-9]|1[0-2])\b")
    hits = [(p.name, m.group()) for p in sources() for m in pat.finditer(p.read_text())]
    assert not hits, f"detection code mentions scenario ids: {hits}"