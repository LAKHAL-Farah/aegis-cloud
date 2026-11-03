"""Stage 3 scoring: alerts are attributed by evidence time, after the whole run."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from attacks.attribution import attribute_alerts  # noqa: E402
from attacks.detection import match_alert  # noqa: E402

T0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
ACCT = "555555555555"


def iso(s):
    return (T0 + timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def row(sid, technique, start, end, hardened="SUCCEEDED"):
    return {"id": sid, "technique": technique, "attack_start": iso(start), "attack_end": iso(end),
            "hardened": {"outcome": hardened}, "purple": {"outcome": "SUCCEEDED"}}


def alert(technique, event_at, detected_at, source="python-engine", rule="R"):
    return {"technique": technique, "account_id": ACCT, "event_time": iso(event_at),
            "detected_at": iso(detected_at), "source": source, "rule": rule, "summary": rule}


def test_a_slow_detector_is_still_credited_after_the_run():
    rows = [row("S04", "T1562.008", 0, 10)]
    attribute_alerts(rows, [alert("T1562.008", 2, 40)], ACCT, 120)
    assert rows[0]["detected"] and abs(rows[0]["mttd"] - 40) < 0.01


def test_same_technique_alert_is_not_credited_to_the_wrong_scenario():
    # S02 and S07 are both T1530. Only S07 produced evidence, 60 s after S02 ended.
    rows = [row("S02", "T1530", 0, 10), row("S07", "T1530", 60, 70)]
    attribute_alerts(rows, [alert("T1530", 62, 65)], ACCT, 120)
    assert [r["detected"] for r in rows] == [False, True]


def test_without_event_time_the_old_rule_applies():
    a = {"technique": "T1530", "account_id": ACCT, "detected_at": iso(5)}
    assert match_alert([a], "T1530", ACCT, T0, 120, t_end=T0 + timedelta(seconds=10)) is not None


def test_alert_for_another_account_never_matches():
    rows = [row("S04", "T1562.008", 0, 10)]
    a = alert("T1562.008", 2, 5)
    a["account_id"] = "444444444444"
    attribute_alerts(rows, [a], ACCT, 120)
    assert not rows[0]["detected"]


def test_alert_outside_the_window_does_not_match():
    rows = [row("S04", "T1562.008", 0, 10)]
    attribute_alerts(rows, [alert("T1562.008", 2, 400)], ACCT, 120)
    assert not rows[0]["detected"]


def test_source_filter_credits_one_detector_only():
    rows = [row("S04", "T1562.008", 0, 10)]
    alerts = [alert("T1562.008", 2, 5, source="wazuh")]
    attribute_alerts(rows, alerts, ACCT, 120, source="python-engine")
    assert not rows[0]["detected"]
    attribute_alerts(rows, alerts, ACCT, 120, source="wazuh")
    assert rows[0]["detected"] and rows[0]["alert_source"] == "wazuh"


def test_unattributed_alerts_are_counted_not_hidden():
    rows = [row("S04", "T1562.008", 0, 10)]
    extra = alert("T1485", 4, 6, rule="AEG-IMPACT-003")
    out = attribute_alerts(rows, [alert("T1562.008", 2, 5), extra], ACCT, 120)
    assert out == {"other_alerts": 1, "other_by_rule": {"AEG-IMPACT-003": 1}}


def test_verdict_combines_with_prevention():
    rows = [row("S04", "T1562.008", 0, 10, hardened="DENIED")]
    attribute_alerts(rows, [alert("T1562.008", 2, 5)], ACCT, 120)
    assert rows[0]["verdict"] == "PREVENTED+DETECTED"