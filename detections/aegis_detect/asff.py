"""Detection -> AWS Security Finding Format (ASFF), so the same findings could be imported into
Security Hub on real AWS (ADR-0002, ADR-0004). Security Hub is not available on LocalStack (501), so
the shape is checked by tests/test_asff.py against the required-field list, not against the live API."""
from __future__ import annotations

from .model import Detection, iso

SEVERITY = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
REQUIRED = ("SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId", "Types", "CreatedAt",
            "UpdatedAt", "Severity", "Title", "Description", "Resources")


def to_asff(d: Detection, region: str = "us-east-1") -> dict:
    when = iso(d.event_time)
    found = iso(d.detected_at or d.event_time)
    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"aegis/{d.rule_id}/{d.account_id}/{d.event_id}",
        "ProductArn": f"arn:aws:securityhub:{region}:{d.account_id}:product/{d.account_id}/default",
        "GeneratorId": f"aegiscloud/{d.source}/{d.rule_id}",
        "AwsAccountId": d.account_id,
        "Types": [f"TTPs/{d.tactic}/{d.technique}"],
        "FirstObservedAt": when,
        "CreatedAt": found,
        "UpdatedAt": found,
        "Severity": {"Label": SEVERITY.get(d.severity, "MEDIUM")},
        "Title": d.title[:256],
        "Description": d.description[:1024],
        "Resources": [{"Type": d.resource_type, "Id": d.resource_id, "Region": region}],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
        "ProductFields": {
            "aegis/technique": d.technique,
            "aegis/tactic": d.tactic,
            "aegis/principal": d.principal,
            "aegis/event_name": d.event_name,
            "aegis/event_id": d.event_id,
            "aegis/event_time": when,
            "aegis/source": d.source,
        },
    }


def to_alert(d: Detection) -> dict:
    """The thin projection the scorer reads (docs/detection-contract.md)."""
    return {
        "technique": d.technique,
        "account_id": d.account_id,
        "detected_at": iso(d.detected_at or d.event_time),
        "event_time": iso(d.event_time),
        "source": d.source,
        "rule": d.rule_id,
        "severity": d.severity,
        "summary": d.summary,
        "raw_event_id": d.event_id,
    }