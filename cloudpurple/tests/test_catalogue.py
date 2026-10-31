"""No LocalStack needed: catalogue integrity + pure scoring/detection logic.
Run with:  python3 -m pytest cloudpurple/tests -q   (also wired into `make range-gate`)
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from attacks import scenarios  # noqa: F401,E402  populates the registry
from attacks.scenario import REGISTRY, TECHNIQUE_RE, all_scenarios  # noqa: E402
from attacks.scoring import DENIED, is_denied, prevented_by, verdict, summarize  # noqa: E402
from attacks.detection import match_alert  # noqa: E402


def test_exactly_twelve_scenarios():
    assert len(REGISTRY) == 12, f"expected 12 scenarios, found {len(REGISTRY)}"


def test_ids_are_s01_through_s12_with_no_gaps():
    ids = {s.id for s in all_scenarios()}
    assert ids == {f"S{i:02d}" for i in range(1, 13)}


def test_every_scenario_has_a_valid_attck_technique():
    for s in all_scenarios():
        assert TECHNIQUE_RE.match(s.technique), f"{s.id} has a malformed technique id: {s.technique!r}"


def test_every_scenario_has_a_tactic_description_and_expected_detection():
    for s in all_scenarios():
        assert s.tactic, f"{s.id} missing tactic"
        assert len(s.description) > 10, f"{s.id} description too short"
        assert len(s.expected_detection) > 10, f"{s.id} expected_detection too short"


def test_data_event_scenarios_have_no_lookup_events_expectation():
    # S02 is only visible as an S3 data event, not through lookup_events.
    for s in all_scenarios():
        if s.data_events:
            assert s.expected_events == ()


def test_non_data_event_scenarios_declare_at_least_one_expected_event():
    for s in all_scenarios():
        if not s.data_events:
            assert len(s.expected_events) >= 1, f"{s.id} must declare expected CloudTrail events"


def test_destructive_scenarios_all_have_a_cleanup():
    noop_name = "_noop"
    for s in all_scenarios():
        if s.destructive:
            assert s.cleanup.__name__ != noop_name, f"{s.id} is destructive and must define cleanup"


def test_shared_techniques_are_a_known_and_accepted_short_list():
    # S02 (exfiltrate objects) and S07 (make the bucket public) are both legitimately
    # "T1530 Data from Cloud Storage". ADR-0009 accepts this: scenarios run sequentially
    # with cleanup between runs, so same-technique cross-matching inside the alert window
    # is rare in practice, and the scorecard prints the matched alert for manual review.
    # This test documents the exception instead of silently allowing new collisions.
    from collections import Counter
    counts = Counter(s.technique for s in all_scenarios())
    duplicated = {t: c for t, c in counts.items() if c > 1}
    assert duplicated == {"T1530": 2}, (
        f"unexpected technique collisions {duplicated}: either it's the known S02/S07 pair "
        "(update this test's expectation) or a new collision was introduced (fix the scenario instead)"
    )


# ---------------------------------------------------------------- scoring


class _FakeError(Exception):
    def __init__(self, code, message, status=400):
        self.response = {"Error": {"Code": code, "Message": message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


def test_is_denied_recognizes_access_denied_code():
    assert is_denied(_FakeError("AccessDenied", "User is not authorized"))


def test_is_denied_recognizes_explicit_deny_message():
    assert is_denied(_FakeError("ClientError", "User: ... is not authorized to perform ... with an explicit deny in a service control policy"))


def test_is_denied_false_for_unrelated_error():
    assert not is_denied(_FakeError("NoSuchBucket", "The specified bucket does not exist"))


def test_prevented_by_names_the_right_layer():
    assert prevented_by("explicit deny in a service control policy") == "SCP"
    assert prevented_by("User is not authorized because it exceeds its permissions boundary") == "permission boundary"


def test_verdict_combines_prevented_and_detected():
    assert verdict(DENIED, True) == "PREVENTED+DETECTED"
    assert verdict(DENIED, False) == "PREVENTED"
    assert verdict("SUCCEEDED", True) == "DETECTED"
    assert verdict("SUCCEEDED", False) == "NEITHER"


def test_summarize_counts_match_rows():
    rows = [
        {"purple": {"outcome": "SUCCEEDED"}, "hardened": {"outcome": "DENIED"}, "detected": False, "verdict": "PREVENTED", "mttd": None},
        {"purple": {"outcome": "SUCCEEDED"}, "hardened": {"outcome": "SUCCEEDED"}, "detected": True, "verdict": "DETECTED", "mttd": 12.5},
        {"purple": {"outcome": "SUCCEEDED"}, "hardened": {"outcome": "SUCCEEDED"}, "detected": False, "verdict": "NEITHER", "mttd": None},
    ]
    s = summarize(rows)
    assert s["total"] == 3
    assert s["prevented"] == 1
    assert s["detected"] == 1
    assert s["neither"] == 1
    assert s["mean_mttd"] == 12.5


# ---------------------------------------------------------------- detection matching


def test_match_alert_requires_same_technique_and_account():
    t0 = datetime(2026, 10, 30, tzinfo=timezone.utc)
    alerts = [{"technique": "T1562.008", "account_id": "555555555555",
               "detected_at": (t0 + timedelta(seconds=5)).isoformat()}]
    assert match_alert(alerts, "T1562.008", "555555555555", t0, 120) is not None
    assert match_alert(alerts, "T1562.007", "555555555555", t0, 120) is None
    assert match_alert(alerts, "T1562.008", "444444444444", t0, 120) is None


def test_match_alert_respects_the_time_window():
    t0 = datetime(2026, 10, 30, tzinfo=timezone.utc)
    alerts = [{"technique": "T1530", "account_id": "555555555555",
               "detected_at": (t0 + timedelta(seconds=500)).isoformat()}]
    assert match_alert(alerts, "T1530", "555555555555", t0, 120) is None


def test_match_alert_picks_the_earliest_match():
    t0 = datetime(2026, 10, 30, tzinfo=timezone.utc)
    alerts = [
        {"technique": "T1530", "account_id": "555555555555", "detected_at": (t0 + timedelta(seconds=40)).isoformat()},
        {"technique": "T1530", "account_id": "555555555555", "detected_at": (t0 + timedelta(seconds=9)).isoformat()},
    ]
    match = match_alert(alerts, "T1530", "555555555555", t0, 120)
    assert match is not None
    assert abs(match[1] - 9.0) < 0.01


# ---------------------------------------------------------------- range isolation (ADR-0006)


def test_stage1_gate_config_never_references_the_range():
    repo_root = HERE.parent
    checkov_cfg = repo_root / "policies" / "checkov" / ".checkov.yaml"
    if checkov_cfg.exists():
        assert "cloudpurple" not in checkov_cfg.read_text()
    tflint_cfg = repo_root / ".tflint.hcl"
    if tflint_cfg.exists():
        assert "cloudpurple" not in tflint_cfg.read_text()