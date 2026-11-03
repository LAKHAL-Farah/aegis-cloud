#!/usr/bin/env python3
"""Stage 3b: read Falco JSON output (one object per line on stdin) and write contract alerts.

  falco -o json_output=true ... | python3 siem/falco_bridge.py
Falco sees containers, not AWS accounts, so every alert is attributed to the purple account (the twin
that owns the cluster in this lab). That is a modelling choice, stated in the scorecard notes."""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import iso, write_alert  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def convert(line: str, account_id: str, now: datetime | None = None) -> dict | None:
    try:
        f = json.loads(line)
    except ValueError:
        return None
    tags = f.get("tags") or []
    technique = next((t for t in tags if TECHNIQUE.match(str(t))), None)
    if "aegis" not in tags or not technique:
        return None
    return {"technique": technique, "account_id": account_id, "detected_at": iso(now or datetime.now(timezone.utc)),
            "event_time": f.get("time"), "source": "falco", "rule": f.get("rule", ""),
            "severity": {"Critical": "critical", "Error": "high", "Warning": "medium"}.get(f.get("priority"), "low"),
            "summary": (f.get("output") or "")[:200]}


def main() -> int:
    targets = json.loads((ROOT / "build" / "range" / "targets.json").read_text())
    account = targets["purple"]["account_id"]
    for line in sys.stdin:
        alert = convert(line, account)
        if alert:
            write_alert(ROOT / "build" / "alerts", alert, alert["rule"].replace(" ", "-"))
            print(f"  ALERT {alert['technique']} {alert['rule']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())