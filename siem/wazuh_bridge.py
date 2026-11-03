#!/usr/bin/env python3
"""Follow the Wazuh manager's alerts.json and write contract alerts (source = "wazuh").

Only rules in the AegisCloud range (100100-100299) are converted. `detected_at` is the time the bridge
sees the alert, which includes the bridge's own latency: that is the honest MTTD for this path."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import iso, write_alert  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RULES_XML = Path(__file__).resolve().parent / "wazuh" / "local_rules.xml"
CONTAINER = "aegis-wazuh"
ALERTS = "/var/ossec/logs/alerts/alerts.json"


def load_techniques(path: Path = RULES_XML) -> dict[str, str]:
    """rule id -> ATT&CK technique, read from OUR rules file. Wazuh's own MITRE database may not know a
    sub-technique (T1555.006 was missing in 4.14.3: the alert fired with no `mitre` block)."""
    import xml.etree.ElementTree as ET
    out = {}
    for rule in ET.parse(path).getroot().iter("rule"):
        mid = rule.find("mitre/id")
        if mid is not None and mid.text:
            out[rule.get("id")] = mid.text.strip()
    return out


TECHNIQUES = load_techniques()


def convert(line: str, now: datetime | None = None) -> dict | None:
    try:
        a = json.loads(line)
    except ValueError:
        return None
    rule = a.get("rule") or {}
    rid = str(rule.get("id", ""))
    if not (rid.isdigit() and 100100 <= int(rid) <= 100299):
        return None
    mitre = [TECHNIQUES[rid]] if rid in TECHNIQUES else ((rule.get("mitre") or {}).get("id") or [])
    data = a.get("data") or {}
    account = str(data.get("aegis_account_id") or "")
    if not mitre or not account:
        return None
    event_time = data.get("eventTime")
    return {
        "technique": mitre[0], "account_id": account, "detected_at": iso(now or datetime.now(timezone.utc)),
        **({"event_time": event_time} if event_time else {}),
        "source": "wazuh", "rule": f"W-{rid}", "severity": "high" if int(rule.get("level", 0)) >= 12 else "medium",
        "summary": rule.get("description", ""), "raw_event_id": str(data.get("eventID", "")),
    }


def main() -> int:
    alert_dir = ROOT / "build" / "alerts"
    cmd = ["docker", "exec", CONTAINER, "tail", "-n", "0", "-F", ALERTS]
    print(f"following {ALERTS} in {CONTAINER} -> {alert_dir}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        alert = convert(line)
        if alert:
            write_alert(alert_dir, alert, alert["raw_event_id"] or alert["rule"])
            print(f"  ALERT {alert['technique']:10} {alert['rule']}  {alert['summary']}", flush=True)
    return proc.wait()


if __name__ == "__main__":
    sys.exit(main())