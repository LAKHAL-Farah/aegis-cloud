"""Where detections go: contract alerts for the scorer, ASFF findings, optionally OpenSearch / EventBridge."""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from .asff import to_alert, to_asff
from .model import Detection, iso


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")           # .tmp is never matched by the scorer's *.json glob
    tmp.write_text(json.dumps(data, indent=2))
    os.replace(tmp, path)


class FileSink:
    def __init__(self, alert_dir: Path, findings_dir: Path, region: str = "us-east-1"):
        self.alert_dir, self.findings_dir, self.region = Path(alert_dir), Path(findings_dir), region

    def emit(self, d: Detection) -> None:
        stamp = (d.detected_at or d.event_time).strftime("%Y%m%dT%H%M%S%f")
        name = f"{stamp}-{d.rule_id}-{d.event_id[:8]}.json"
        _atomic_write(self.alert_dir / name, to_alert(d))
        _atomic_write(self.findings_dir / name, to_asff(d, self.region))


class OpenSearchSink:
    """Index findings into OpenSearch with a plain HTTP call (no client library)."""

    def __init__(self, url: str, region: str = "us-east-1"):
        self.url, self.region = url.rstrip("/"), region

    def emit(self, d: Detection) -> None:
        doc = {**to_asff(d, self.region), "technique": d.technique, "tactic": d.tactic, "rule": d.rule_id,
               "severity": d.severity, "account_id": d.account_id, "event_time": iso(d.event_time),
               "detected_at": iso(d.detected_at or d.event_time), "source": d.source,
               "mttd_hint_s": (d.detected_at - d.event_time).total_seconds() if d.detected_at else None}
        index = f"aegis-findings-{d.event_time:%Y.%m}"
        req = urllib.request.Request(f"{self.url}/{index}/_doc/{d.rule_id}-{d.event_id}",
                                     data=json.dumps(doc).encode(), method="PUT",
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()


class EventBridgeSink:
    """Publish the ASFF finding on a bus: the hook Stage 4 (response) subscribes to (ADR-0005)."""

    def __init__(self, client, bus: str = "aegis-findings", region: str = "us-east-1"):
        self.client, self.bus, self.region = client, bus, region

    def emit(self, d: Detection) -> None:
        self.client.put_events(Entries=[{
            "Source": "aegiscloud.detection", "DetailType": "AegisFinding", "EventBusName": self.bus,
            "Detail": json.dumps(to_asff(d, self.region))}])


class SafeSink:
    """Wrap an optional sink so a SIEM outage never stops detection."""

    def __init__(self, inner, label: str):
        self.inner, self.label = inner, label

    def emit(self, d: Detection) -> None:
        try:
            self.inner.emit(d)
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] sink {self.label} failed: {exc}")


class OpenSearchEvents:
    """Bulk-index the raw events (the 'timeline' side of the dashboards). Plain HTTP, no client library."""

    def __init__(self, url: str):
        self.url = url.rstrip("/")

    @staticmethod
    def bulk_body(events) -> str:
        lines = []
        for e in events:
            if e.category == "Observation":
                continue
            lines.append(json.dumps({"index": {"_index": f"aegis-events-{e.time:%Y.%m.%d}", "_id": e.id}}))
            lines.append(json.dumps({
                "event_time": iso(e.time), "account_id": e.account_id, "event_name": e.name, "service": e.service,
                "principal": e.principal, "identity": e.identity_name, "user_agent": e.user_agent,
                "source_ip": e.source_ip, "error_code": e.error_code, "category": e.category}))
        return "\n".join(lines) + "\n" if lines else ""

    def index(self, events) -> None:
        body = self.bulk_body(events)
        if not body:
            return
        req = urllib.request.Request(f"{self.url}/_bulk", data=body.encode(), method="POST",
                                     headers={"Content-Type": "application/x-ndjson"})
        urllib.request.urlopen(req, timeout=10).read()