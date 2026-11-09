"""ADR-0013 for Sentinel: it must find weaknesses by what the IAM says, never by the names in the lab."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ["cloudpurple", "dev-svc", "intern", "backdoor", "999999999999", "555555555555", "444444444444", "purple-trail",
             "attacker", "run_id", "unknown-laptop", "data_bucket"]


def sources():
    return list((ROOT / "aegis_sentinel").rglob("*.py")) + [ROOT / "policy.json", ROOT / "sentinel.py"]


def test_no_lab_names_in_sentinel_code():
    hits = [(p.name, s) for p in sources() for s in FORBIDDEN if s in p.read_text().lower()]
    assert not hits, f"sentinel references the range: {hits}"


def test_no_scenario_ids_in_sentinel_code():
    pat = re.compile(r"\bS(0[1-9]|1[0-2])\b")
    assert not [(p.name, m.group()) for p in sources() for m in pat.finditer(p.read_text())]


def test_expected_admins_are_patterns_not_account_ids():
    import json
    pol = json.loads((ROOT / "policy.json").read_text())
    assert pol["expected_admins"] and not any(re.search(r"\d{12}", p) for p in pol["expected_admins"])


def test_sentinel_never_calls_a_changing_iam_api():
    """It is read-only by construction: no Create/Put/Attach/Delete/Update client call exists in the package."""
    bad = re.compile(r"\.(create|put|attach|delete|update|add|remove|set|detach)_[a-z_]+\(")
    hits = [(p.name, m.group()) for p in (ROOT / "aegis_sentinel").rglob("*.py") for m in bad.finditer(p.read_text())]
    assert not hits, hits
