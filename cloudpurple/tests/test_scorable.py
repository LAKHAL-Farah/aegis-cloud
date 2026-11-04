"""ADR-0014: a scenario may leave the scorable denominator only with a written, evidenced reason."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

from attacks.scoring import KNOWN_LIMITS, headline, load_known_limits, render_markdown, scorable_counts, summarize  # noqa: E402

ROWS = [{"id": "S01", "detected": True, "mttd": 2.0, "verdict": "DETECTED", "name": "a", "technique": "T1", "purple": {"outcome": "SUCCEEDED"}, "hardened": {"outcome": "SUCCEEDED"}},
        {"id": "S08", "detected": False, "mttd": None, "verdict": "NEITHER", "name": "b", "technique": "T2", "purple": {"outcome": "SUCCEEDED"}, "hardened": {"outcome": "SUCCEEDED"}}]


def test_without_exclusions_nothing_changes():
    s = summarize(ROWS)
    assert s["total"] == 2 and s["detected"] == 1 and s["scorable"] == 2 and s["excluded"] == []
    assert headline(s).startswith("Detected: 1 of 2  |")


def test_headline_never_prints_a_bare_n_of_n_when_something_is_excluded():
    s = summarize(ROWS, {"S08": "x"})
    h = headline(s)
    assert h.startswith("Detected: 1 of 1 scorable (2 run, S08 excluded: LocalStack limitation)")
    assert s["detected"] == 1 and s["total"] == 2          # the raw counts are still there


def test_excluded_row_is_marked_in_the_markdown():
    md = render_markdown("l", "now", ROWS, summarize(ROWS, {"S08": "why"}), {"S08": "why"})
    assert "NEITHER (excluded)" in md and "S08 is excluded from the scorable count: why" in md


def test_scorable_counts_work_on_rows_alone():
    assert scorable_counts(ROWS, {"S08": "x"}) == {"run": 2, "scorable": 1, "excluded": ["S08"], "detected_scorable": 1}


def test_every_known_limit_cites_evidence_in_the_repo():
    limits = load_known_limits()
    assert limits, "expected at least the S08 entry"
    root = KNOWN_LIMITS.parents[1]
    for sid, why in limits.items():
        assert len(why) > 40, f"{sid}: a one-word reason is not enough to leave the denominator"
        cited = [w.strip(".,;:()") for w in why.split() if w.strip(".,;:()").startswith("docs/evidence/")]
        assert cited, f"{sid}: cite a file under docs/evidence/ that shows the limitation"
        for path in cited:
            assert (root / path).exists(), f"{sid}: {path} does not exist"
