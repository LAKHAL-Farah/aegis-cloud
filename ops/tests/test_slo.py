import json
from datetime import datetime, timezone

from aegis_ops import slo

NOW = datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc).timestamp()


def iso(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def test_judge_status_and_error_budget():
    s = {"id": "x", "title": "X", "target": 0.99}
    assert slo.judge(s, 100, 100).status == "OK" and slo.judge(s, 100, 100).budget_left == 1.0
    r = slo.judge(s, 99, 100)                       # exactly the target: budget fully spent but not breached
    assert r.status == "AT RISK" and r.budget_left == 0.0
    r = slo.judge(s, 90, 100)
    assert r.status == "BREACHED" and r.budget_left < 0
    assert slo.judge(s, 0, 0).status == "NO DATA"
    assert "not enough" in slo.judge(s, 3, 3).note


def test_zero_allowed_failures():
    s = {"id": "x", "title": "X", "target": 1.0}
    assert slo.judge(s, 5, 5).budget_left == 1.0 and slo.judge(s, 4, 5).status == "BREACHED"


def test_availability_counts_ticks_where_every_listed_component_was_up(tmp_path):
    log = tmp_path / "health.jsonl"
    ticks = [(NOW - 50, True, True), (NOW - 40, True, False), (NOW - 30, True, True), (NOW - 99999, False, False)]
    log.write_text("\n".join(json.dumps({"ts": t, "components": {"localstack": {"up": a}, "detector": {"up": b}}})
                             for t, a, b in ticks) + "\nnot json\n")
    slo_cfg = {"id": "a", "title": "A", "kind": "availability", "components": ["localstack", "detector"], "target": 0.5}
    r = slo.availability(slo_cfg, log, NOW - 3600)
    assert (r.good, r.total) == (2, 3)                 # the old tick and the garbage line are ignored


def test_availability_ignores_ticks_where_a_probe_did_not_run(tmp_path):
    log = tmp_path / "h.jsonl"
    log.write_text(json.dumps({"ts": NOW, "components": {"localstack": {"up": True}}}) + "\n")
    r = slo.availability({"id": "a", "title": "A", "components": ["localstack", "detector"], "target": 0.9}, log, 0)
    assert r.total == 0 and r.status == "NO DATA"


def outcome(ts, status, **timings):
    return {"seq": 1, "ts": iso(ts), "incident": "i", "step": "outcome", "status": status, "data": {"timings": timings}}


def test_response_speed_counts_contained_in_time_and_failures_but_not_human_decisions(tmp_path):
    audit = tmp_path / "audit.jsonl"
    recs = [outcome(NOW - 10, "contained", machine_s=0.3), outcome(NOW - 9, "contained", machine_s=9.0),
            outcome(NOW - 8, "partial", machine_s=1.0), outcome(NOW - 7, "denied"), outcome(NOW - 6, "timeout"),
            outcome(NOW - 5, "refused"), {"step": "approval", "ts": iso(NOW), "status": "ok", "incident": "i", "data": {}},
            outcome(NOW - 99999, "contained", machine_s=0.1)]
    audit.write_text("\n".join(json.dumps(r) for r in recs))
    cfg = {"id": "r", "title": "R", "kind": "response", "metric": "machine_s", "threshold_s": 5, "target": 0.9}
    r = slo.response_speed(cfg, audit, NOW - 3600)
    assert (r.good, r.total) == (1, 3) and r.extra["worst_s"] == 9.0


def test_freshness_reads_asff_created_at_minus_event_time(tmp_path):
    d = tmp_path / "findings"
    d.mkdir()
    for i, delay in enumerate([2, 14, 45]):
        (d / f"{i}.json").write_text(json.dumps({"CreatedAt": iso(NOW - 5), "ProductFields": {"aegis/event_time": iso(NOW - 5 - delay)}}))
    (d / "junk.json").write_text("{")
    r = slo.freshness({"id": "f", "title": "F", "threshold_s": 30, "target": 0.9}, d, NOW - 3600)
    assert (r.good, r.total) == (2, 3) and r.extra["worst_s"] == 45.0


def test_evaluate_and_render(tmp_path):
    cfg = json.loads((__import__("pathlib").Path(__file__).resolve().parents[1] / "slo.json").read_text())
    res = slo.evaluate(cfg, health_log=tmp_path / "none", audit_path=tmp_path / "none", findings_dir=tmp_path / "none", now=NOW)
    assert [r.status for r in res] == ["NO DATA"] * 3
    md = slo.render_markdown(res, 24, "stamp")
    assert "Detection path is up" in md and "NO DATA" in md
    json.dumps(slo.to_json(res))


def test_unknown_kind_is_an_error(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        slo.evaluate({"slos": [{"id": "x", "kind": "magic"}]}, health_log=tmp_path, audit_path=tmp_path, findings_dir=tmp_path, now=NOW)


def test_deliberate_chaos_windows_are_not_counted(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join(json.dumps(r) for r in [
        {"ts": NOW - 100, "action": "chaos-start"}, {"ts": NOW - 50, "action": "chaos-end"},
        {"ts": NOW - 10, "action": "restart"}]) + "\n")
    assert slo.chaos_windows(events) == [(NOW - 100, NOW - 50)]
    log = tmp_path / "health.jsonl"
    log.write_text("\n".join(json.dumps({"ts": t, "components": {"detector": {"up": up}}})
                             for t, up in [(NOW - 90, False), (NOW - 60, False), (NOW - 20, True), (NOW - 10, True)]) + "\n")
    cfg = {"id": "a", "title": "A", "components": ["detector"], "target": 0.9}
    assert slo.availability(cfg, log, 0).good == 2 and slo.availability(cfg, log, 0).total == 4
    r = slo.availability(cfg, log, 0, skip=slo.chaos_windows(events))
    assert (r.good, r.total) == (2, 2)


def test_an_unfinished_chaos_window_excludes_everything_after_it(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text(json.dumps({"ts": NOW - 5, "action": "chaos-start"}) + "\n")
    assert slo._excluded(NOW, slo.chaos_windows(events))


def test_maintenance_windows_and_the_epoch(tmp_path):
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join(json.dumps(r) for r in [
        {"ts": NOW - 100, "action": "maintenance-start"}, {"ts": NOW - 60, "action": "maintenance-end"},
        {"ts": NOW - 5, "action": "maintenance-start"}]) + "\n")
    assert slo.maintenance_windows(events) == [(NOW - 100, NOW - 60), (NOW - 5, float("inf"))]
    assert slo.in_maintenance(events)
    events.write_text(json.dumps({"ts": NOW, "action": "maintenance-end"}) + "\n")
    assert not slo.in_maintenance(events)


def test_epoch_ignores_older_history(tmp_path):
    log = tmp_path / "h.jsonl"
    log.write_text("\n".join(json.dumps({"ts": t, "components": {"detector": {"up": up}}})
                             for t, up in [(NOW - 100, False), (NOW - 90, False), (NOW - 10, True)]) + "\n")
    cfg = {"window_h": 24, "slos": [{"id": "a", "title": "A", "kind": "availability", "components": ["detector"], "target": 0.9}]}
    kw = dict(health_log=log, audit_path=tmp_path / "x", findings_dir=tmp_path / "y", now=NOW)
    assert slo.evaluate(cfg, **kw)[0].total == 3
    assert slo.evaluate(cfg, epoch=NOW - 50, **kw)[0].total == 1
