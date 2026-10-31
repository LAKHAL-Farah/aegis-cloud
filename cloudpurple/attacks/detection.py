"""Telemetry (did CloudTrail record it?) and detection (did anything alert?)."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def telemetry_status(ct, events, since, timeout: int = 12):
    """Look for each expected event name in CloudTrail since `since`. Returns (FULL|PARTIAL|NONE, found)."""
    found: set[str] = set()
    deadline = time.time() + timeout
    while True:
        for name in events:
            if name in found:
                continue
            try:
                resp = ct.lookup_events(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                    StartTime=since, MaxResults=20)
            except Exception:
                resp = {}
            if resp.get("Events"):
                found.add(name)
        if len(found) == len(events) or time.time() >= deadline:
            break
        time.sleep(2)
    if len(found) == len(events):
        return "FULL", sorted(found)
    return ("PARTIAL" if found else "NONE"), sorted(found)


def _parse(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def load_alerts(directory) -> list[dict]:
    """Every *.json file in `directory`: one alert object or a list of them (docs/detection-contract.md)."""
    alerts: list[dict] = []
    d = Path(directory)
    if not d.is_dir():
        return alerts
    for f in sorted(d.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        alerts.extend(data if isinstance(data, list) else [data])
    return alerts


def match_alert(alerts, technique: str, account_id: str, t0: datetime, window: int):
    """First alert with the same technique + account inside [t0 - 1 s, t0 + window]. Returns (alert, mttd) or None."""
    best = None
    for a in alerts:
        try:
            when = _parse(a["detected_at"])
        except (KeyError, ValueError):
            continue
        if a.get("technique") != technique or str(a.get("account_id")) != str(account_id):
            continue
        delta = (when - t0).total_seconds()
        if -1 <= delta <= window and (best is None or delta < best[1]):
            best = (a, max(delta, 0.0))
    return best