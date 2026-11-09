"""Scan results -> ASFF posture findings (same shape as detections, ADR-0002).

These describe a standing condition, not an event. They go to build/sentinel/findings/, NOT build/findings/, because
the responder watches the second directory and a posture finding is not an incident to contain."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from .escalation import CATALOGUE

RULES = {"escalates": ("AEG-IAM-001", "HIGH", "Privilege Escalation"), "admin": ("AEG-IAM-002", "HIGH", "Privilege Escalation")}


def to_asff(scan: dict, region: str = "us-east-1") -> list[dict]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    acct, out = scan["account_id"], []
    for arn, p in sorted(scan["principals"].items()):
        if p["category"] not in RULES:
            continue
        rule, sev, tactic = RULES[p["category"]]
        first = p["path"][0] if p["path"] else {}
        tech = first.get("attack") or CATALOGUE["ADMIN"]["attack"]
        route = " -> ".join([p["name"]] + [s["to"] for s in p["path"]]) if p["path"] else p["name"]
        title = (f"{p['kind'].title()} {p['name']} can reach admin in {p['hops']} step(s)" if p["category"] == "escalates"
                 else f"{p['kind'].title()} {p['name']} is admin (Allow * on *)")
        out.append({
            "SchemaVersion": "2018-10-08",
            "Id": f"aegis/{rule}/{acct}/{hashlib.sha256((arn + route).encode()).hexdigest()[:16]}",
            "ProductArn": f"arn:aws:securityhub:{region}:{acct}:product/{acct}/default",
            "GeneratorId": f"aegiscloud/sentinel/{rule}", "AwsAccountId": acct, "Types": [f"TTPs/{tactic}/{tech}"],
            "FirstObservedAt": now, "CreatedAt": now, "UpdatedAt": now, "Severity": {"Label": sev},
            "Title": title[:256],
            "Description": (f"Path: {route}. Techniques: {', '.join(s['technique'] for s in p['path']) or 'ADMIN'}. "
                            f"Fix: {CATALOGUE[first.get('technique', 'ADMIN')]['fix']}")[:1024],
            "Resources": [{"Type": "AwsIamUser" if p["kind"] == "user" else "AwsIamRole", "Id": arn, "Region": region}],
            "RecordState": "ACTIVE", "Workflow": {"Status": "NEW"},
            "ProductFields": {"aegis/technique": tech, "aegis/tactic": tactic, "aegis/principal": arn, "aegis/source": "sentinel",
                              "aegis/path": route, "aegis/kind": "posture"},
        })
    return out
