import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attack_matrix import build, miss_reason  # noqa: E402


def card(label, rows, detected):
    return {"label": label, "rows": rows, "summary": {"detected": detected, "total": len(rows), "prevented": 1,
            "mean_mttd": 4.0 if detected else None, "other_alerts": 2}}


def row(sid, tactic, technique, detected, tele="FULL", mttd=None):
    return {"id": sid, "name": f"scenario {sid}", "technique": technique, "tactic": tactic, "detected": detected,
            "mttd": mttd, "alert_rule": "AEG-X", "alert_source": "python-engine",
            "purple": {"outcome": "SUCCEEDED", "telemetry": tele}}


def test_matrix_reports_numbers_misses_and_reasons():
    before = card("baseline", [row("S01", "Discovery", "T1580", False), row("S02", "Collection", "T1530", False, "DATA-EVENT")], 0)
    after = card("v1", [row("S01", "Discovery", "T1580", True, mttd=3.2), row("S02", "Collection", "T1530", False, "DATA-EVENT")], 1)
    md, page = build(before, after)
    assert "**1 of 2**" in md and "3.2 s" in md and "needs S3 data events" in md
    assert 'class="cell ok"' in page and 'class="cell miss"' in page and "<script" not in page


def test_miss_reasons():
    assert "no telemetry" in miss_reason(row("S04", "Defense Evasion", "T1562.008", False, "NONE"))
    assert "no rule fired" in miss_reason(row("S01", "Discovery", "T1580", False, "FULL"))

def test_known_limitation_replaces_the_generic_reason():
    before = card("b", [row("S08", "Initial Access", "T1078.004", False)], 0)
    after = card("a", [row("S08", "Initial Access", "T1078.004", False)], 0)
    md, _ = build(before, after, {"S08": "LocalStack overwrites the user agent"})
    assert "known limitation: LocalStack overwrites the user agent" in md and "investigate" not in md
