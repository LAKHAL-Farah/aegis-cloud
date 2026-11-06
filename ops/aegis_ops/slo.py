"""SLOs computed from what the pipeline already writes (ADR-0017). No CloudWatch needed, so the numbers are the same
on LocalStack and on real AWS.

SLI sources
* availability: watchdog health.jsonl            (a tick is good when every listed component was up)
* response speed: the responder's audit trail    (`outcome` records carry the timings)
* detection freshness: the ASFF findings         (CreatedAt minus aegis/event_time)

A target means little on a handful of events, so every row carries n and a note when n is small.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MIN_EVENTS = 20


@dataclass
class SloResult:
    id: str
    title: str
    target: float
    good: int
    total: int
    sli: float | None
    status: str                     # OK | AT RISK | BREACHED | NO DATA
    budget_left: float | None       # 1.0 = untouched, 0 = spent, negative = overspent
    note: str = ""
    extra: dict = field(default_factory=dict)


def _parse(ts: str) -> float:
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()


def judge(slo: dict, good: int, total: int, extra: dict | None = None, note: str = "") -> SloResult:
    target = float(slo["target"])
    if total == 0:
        return SloResult(slo["id"], slo["title"], target, 0, 0, None, "NO DATA", None, "no events in the window", extra or {})
    sli = good / total
    allowed_bad = (1 - target) * total
    bad = total - good
    left = round(1 - bad / allowed_bad, 6) if allowed_bad > 1e-9 else (1.0 if bad == 0 else -math.inf)
    status = "BREACHED" if round(sli, 9) < round(target, 9) else "AT RISK" if left < 0.25 else "OK"
    if total < MIN_EVENTS:
        note = (note + " " if note else "") + f"only {total} events: not enough to say the target holds"
    return SloResult(slo["id"], slo["title"], target, good, total, sli, status, left, note, extra or {})


def _lines(path: Path):
    try:
        for line in Path(path).read_text().splitlines():
            if line.strip():
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def _windows(events_log: Path, start_action: str, end_action: str) -> list[tuple[float, float]]:
    out, start = [], None
    for rec in _lines(events_log):
        if rec.get("action") == start_action:
            start = rec["ts"]
        elif rec.get("action") == end_action and start is not None:
            out.append((start, rec["ts"]))
            start = None
    if start is not None:
        out.append((start, float("inf")))
    return out


def chaos_windows(events_log: Path) -> list[tuple[float, float]]:
    """Intervals the chaos harness broke things on purpose (chaos-start / chaos-end in events.jsonl)."""
    return _windows(events_log, "chaos-start", "chaos-end")


def maintenance_windows(events_log: Path) -> list[tuple[float, float]]:
    """Intervals a person stopped the stack on purpose (`ops.py down` .. `ops.py up`). Down on purpose is not down."""
    return _windows(events_log, "maintenance-start", "maintenance-end")


def in_maintenance(events_log: Path) -> bool:
    return any(end == float("inf") for _, end in maintenance_windows(events_log))


def _excluded(ts: float, windows) -> bool:
    return any(a <= ts <= b for a, b in windows)


def availability(slo: dict, health_log: Path, since: float, skip=()) -> SloResult:
    comps = slo["components"]
    good = total = 0
    for rec in _lines(health_log):
        if rec["ts"] < since or _excluded(rec["ts"], skip):
            continue
        seen = [rec["components"].get(c) for c in comps]
        if any(s is None for s in seen):
            continue                                   # a probe that was not running says nothing
        total += 1
        good += all(s["up"] for s in seen)
    return judge(slo, good, total)


def response_speed(slo: dict, audit_path: Path, since: float, skip=()) -> SloResult:
    """Good = CONTAINED within threshold. PARTIAL and FAILED are bad. DENIED, TIMEOUT, REFUSED, NOOP are people or
    policy deciding, not the service failing, so they are not events."""
    metric, limit = slo["metric"], float(slo["threshold_s"])
    good = total = 0
    worst = 0.0
    for rec in _lines(audit_path):
        if rec.get("step") != "outcome" or _parse(rec["ts"]) < since or _excluded(_parse(rec["ts"]), skip):
            continue
        status = rec["status"]
        if status not in ("contained", "partial", "failed"):
            continue
        total += 1
        value = (rec.get("data", {}).get("timings") or {}).get(metric)
        ok = status == "contained" and value is not None and value <= limit
        good += ok
        worst = max(worst, value or 0.0)
    return judge(slo, good, total, {"worst_s": round(worst, 3)})


def freshness(slo: dict, findings_dir: Path, since: float, skip=()) -> SloResult:
    limit = float(slo["threshold_s"])
    good = total = 0
    worst = 0.0
    for path in sorted(Path(findings_dir).glob("*.json")):
        try:
            f = json.loads(path.read_text())
            created = _parse(f["CreatedAt"])
            happened = _parse((f.get("ProductFields") or {}).get("aegis/event_time") or f["CreatedAt"])
        except (OSError, ValueError, KeyError):
            continue
        if created < since or _excluded(created, skip):
            continue
        total += 1
        delay = max(0.0, created - happened)
        good += delay <= limit
        worst = max(worst, delay)
    return judge(slo, good, total, {"worst_s": round(worst, 3)})


def evaluate(config: dict, *, health_log: Path, audit_path: Path, findings_dir: Path, now: float,
             events_log: Path | None = None, epoch: float = 0.0) -> list[SloResult]:
    """epoch: ignore everything before it (`ops.py slo --reset`), so an old messy history can be left behind without deleting it."""
    since = max(now - float(config.get("window_h", 24)) * 3600, epoch)
    skip = (chaos_windows(events_log) + maintenance_windows(events_log)) if events_log else []
    out = []
    for slo in config["slos"]:
        kind = slo["kind"]
        if kind == "availability":
            out.append(availability(slo, health_log, since, skip))
        elif kind == "response":
            out.append(response_speed(slo, audit_path, since, skip))
        elif kind == "freshness":
            out.append(freshness(slo, findings_dir, since, skip))
        else:
            raise ValueError(f"unknown SLO kind {kind!r}")
    return out


def render_markdown(results: list[SloResult], window_h: float, stamp: str) -> str:
    rows = ["| SLO | Target | SLI | Events | Error budget left | Status |", "| --- | --- | --- | --- | --- | --- |"]
    for r in results:
        sli = "-" if r.sli is None else f"{r.sli * 100:.2f}%"
        left = "-" if r.budget_left is None else ("overspent" if r.budget_left < 0 else f"{r.budget_left * 100:.0f}%")
        rows.append(f"| {r.title} | {r.target * 100:.1f}% | {sli} | {r.good}/{r.total} | {left} | **{r.status}** |")
    notes = [f"* {r.title}: {r.note}" for r in results if r.note]
    return "\n".join([f"# SLO report (last {window_h:g} h, generated {stamp})", "", *rows, "", *notes]) + "\n"


def to_json(results: list[SloResult]) -> list[dict]:
    return [{**r.__dict__, "budget_left": None if r.budget_left is None or math.isinf(r.budget_left) else r.budget_left}
            for r in results]


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
