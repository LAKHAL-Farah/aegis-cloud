"""An Incident is an ASFF finding from the detection engine, flattened to what a playbook needs."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

REQUIRED = ("Id", "GeneratorId", "AwsAccountId", "Types", "Severity", "Title", "Resources", "CreatedAt")
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Incident:
    id: str
    rule: str
    source: str
    technique: str
    tactic: str
    severity: str
    account_id: str
    principal: str
    resource_type: str
    resource_id: str
    event_name: str
    event_id: str
    title: str
    event_time: datetime
    detected_at: datetime
    access_key_id: str = ""

    @property
    def short(self) -> str:
        """12 hex chars: safe in file names and Telegram callback data (64 byte limit)."""
        return hashlib.sha256(self.id.encode()).hexdigest()[:12]

    @property
    def identity(self) -> str:
        return self.principal.rsplit("/", 1)[-1] if "/" in self.principal else self.principal.rsplit(":", 1)[-1]

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    @classmethod
    def from_asff(cls, f: dict) -> "Incident":
        missing = [k for k in REQUIRED if not f.get(k)]
        if missing:
            raise ValueError(f"not an AegisCloud finding, missing {missing}")
        gen = str(f["GeneratorId"]).split("/")          # aegiscloud/<source>/<rule>
        if len(gen) != 3 or gen[0] != "aegiscloud":
            raise ValueError(f"unexpected GeneratorId {f['GeneratorId']!r}")
        pf = f.get("ProductFields") or {}
        types = str(f["Types"][0]).split("/")            # TTPs/<tactic>/<technique>
        res = f["Resources"][0]
        return cls(
            id=str(f["Id"]), rule=gen[2], source=gen[1],
            technique=str(pf.get("aegis/technique") or (types[2] if len(types) > 2 else "")),
            tactic=str(pf.get("aegis/tactic") or (types[1] if len(types) > 1 else "")),
            severity=str((f["Severity"] or {}).get("Label", "")).lower(), account_id=str(f["AwsAccountId"]),
            principal=str(pf.get("aegis/principal", "")), resource_type=str(res.get("Type", "")),
            resource_id=str(res.get("Id", "")), event_name=str(pf.get("aegis/event_name", "")),
            event_id=str(pf.get("aegis/event_id", "")), title=str(f["Title"]),
            event_time=parse_time(pf.get("aegis/event_time") or f["CreatedAt"]), detected_at=parse_time(f["CreatedAt"]),
            access_key_id=str(pf.get("aegis/access_key_id", "")),
        )

    def public(self) -> dict:
        """What is safe to put in a chat message or an audit line."""
        return {"incident_id": self.short, "rule": self.rule, "technique": self.technique, "severity": self.severity,
                "account_id": self.account_id, "principal": self.principal, "resource": self.resource_id,
                "title": self.title}
