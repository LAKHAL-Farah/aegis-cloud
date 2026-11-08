"""What the triage looks up. Read-only, local files only, and each source may be absent."""
from __future__ import annotations

import json
import time
from pathlib import Path

WINDOW_S = 900
SCAN_MAX_AGE_S = 24 * 3600
MAX_FILES = 500


def related(inc, findings_dir, window_s: float = WINDOW_S) -> list[str]:
    """Rule ids of OTHER findings about the same principal within the window, newest first."""
    d = Path(findings_dir) if findings_dir else None
    if not d or not d.is_dir():
        return []
    from aegis_respond.incident import Incident          # imported late: the package works without the responder on the path for tests of text.py
    out = []
    for f in sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:MAX_FILES]:
        try:
            other = Incident.from_asff(json.loads(f.read_text()))
        except (ValueError, KeyError, TypeError, IndexError, OSError):
            continue
        if other.id == inc.id or other.principal != inc.principal or not inc.principal:
            continue
        if abs((other.event_time - inc.event_time).total_seconds()) <= window_s:
            out.append(other.rule)
    return out


def exposure(inc, scan_path, now=time.time, max_age_s: float = SCAN_MAX_AGE_S) -> dict:
    """What IAM Sentinel says about this principal: admin, can escalate (and in how many steps), capped, or ordinary."""
    p = Path(scan_path) if scan_path else None
    if not p or not p.is_file():
        return {"known": False, "why": "no scan"}
    try:
        data = json.loads(p.read_text())
    except (ValueError, OSError):
        return {"known": False, "why": "unreadable scan"}
    if now() - p.stat().st_mtime > max_age_s:
        return {"known": False, "why": "scan older than 24 h"}
    acct = (data.get("accounts") or {}).get(inc.account_id) or {}
    principals = acct.get("principals") or {}
    hit = principals.get(inc.principal) or next((v for v in principals.values() if v.get("name") == inc.identity), None)
    if not hit:
        return {"known": False, "why": "principal not in the scan"}
    return {"known": True, "category": hit["category"], "hops": hit.get("hops", 0),
            "techniques": [s["technique"] for s in hit.get("path", [])]}
