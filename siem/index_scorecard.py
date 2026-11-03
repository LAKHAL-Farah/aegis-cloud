#!/usr/bin/env python3
"""Load scorecard rows into OpenSearch so Dashboards can draw the ATT&CK heatmap.
Usage: python3 siem/index_scorecard.py baseline stage3-v1"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OS = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")


def bulk_lines(label: str, card: dict) -> list[str]:
    out = []
    fallback = card.get("generated", "").replace(" UTC", "").replace(" ", "T") + ":00Z"
    for r in card["rows"]:
        doc = {"label": label, "id": r["id"], "technique": r["technique"], "tactic": r["tactic"],
               "verdict": r["verdict"], "telemetry": (r.get("purple") or {}).get("telemetry", "-").split(" ")[0],
               "detected": bool(r.get("detected")), "mttd": r.get("mttd"), "alert_source": r.get("alert_source"),
               "alert_rule": r.get("alert_rule"), "attack_start": r.get("attack_start") or fallback}
        out += [json.dumps({"index": {"_index": "aegis-scorecards", "_id": f"{label}-{r['id']}"}}), json.dumps(doc)]
    return out


def main(labels: list[str]) -> int:
    if not labels:
        print(__doc__)
        return 1
    lines: list[str] = []
    for label in labels:
        lines += bulk_lines(label, json.loads((ROOT / "docs" / "evidence" / "scorecards" / f"{label}.json").read_text()))
    req = urllib.request.Request(f"{OS}/_bulk?refresh=true", data=("\n".join(lines) + "\n").encode(), method="POST",
                                 headers={"Content-Type": "application/x-ndjson"})
    resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
    print(f"indexed {len(lines) // 2} rows from {', '.join(labels)} (errors: {resp.get('errors')})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))