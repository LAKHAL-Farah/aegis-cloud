"""Attribute alerts to scenarios AFTER the whole run (Stage 3).

Stage 2 looked for alerts about 1 s after each scenario, so any detector slower than that was scored as a
miss. Now the runner records every scenario's start and end, waits for the detectors to settle, and
scores once. `--rescore` runs the same function over a saved scorecard, with no attacks."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from .detection import _parse, match_alert
from .scoring import verdict


def attribute_alerts(rows: list[dict], alerts: list[dict], account_id: str, window: int,
                     slop: float = 1.0, source: str | None = None) -> dict:
    """Fill detected / mttd / alert / verdict on each row. Returns {'other_alerts': n, 'other_by_rule': {...}}."""
    used: set[int] = set()
    for row in rows:
        t0, t1 = _parse(row["attack_start"]), _parse(row["attack_end"])
        match = match_alert(alerts, row["technique"], account_id, t0, window, t_end=t1, slop=slop, source=source)
        row["detected"] = match is not None
        row["mttd"] = match[1] if match else None
        row["alert"] = (match[0].get("summary") or match[0].get("rule")) if match else None
        row["alert_source"] = match[0].get("source") if match else None
        row["alert_rule"] = match[0].get("rule") if match else None
        row["verdict"] = verdict((row.get("hardened") or {}).get("outcome"), row["detected"])
        if match:
            used.add(id(match[0]))

    lo = min(_parse(r["attack_start"]) for r in rows) if rows else None
    hi = max(_parse(r["attack_end"]) for r in rows) if rows else None
    extras = []
    for a in alerts:
        if id(a) in used or str(a.get("account_id")) != str(account_id):
            continue
        if source and a.get("source") != source:
            continue
        try:
            when = _parse(a.get("event_time") or a["detected_at"])
        except (KeyError, ValueError):
            continue
        if lo and hi and lo.timestamp() - slop <= when.timestamp() <= hi.timestamp() + slop:
            extras.append(a)
    return {"other_alerts": len(extras), "other_by_rule": dict(Counter(a.get("rule", "?") for a in extras))}