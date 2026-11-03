"""Write a contract alert (docs/detection-contract.md) from a non-Python detector."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_alert(alert_dir: Path, alert: dict, key: str) -> Path:
    alert_dir = Path(alert_dir)
    alert_dir.mkdir(parents=True, exist_ok=True)
    name = f"{alert['detected_at'].replace(':', '').replace('-', '').replace('.', '')}-{alert['source']}-{key[:12]}.json"
    path = alert_dir / name
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(alert, indent=2))
    os.replace(tmp, path)
    return path