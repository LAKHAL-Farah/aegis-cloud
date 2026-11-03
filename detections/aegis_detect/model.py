"""Event and Detection: the two types every rule, source and sink agree on."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .util import as_obj


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Event:
    """One CloudTrail record, normalised. `raw` keeps the original for forensics and SIEM export."""
    id: str
    time: datetime
    account_id: str
    service: str            # eventSource, e.g. "s3.amazonaws.com"
    name: str               # eventName, e.g. "StopLogging"
    principal: str          # best identity we can find (arn, user name, access key, or "unknown")
    identity_name: str      # last path element: "dev-svc", "root", "unknown"
    user_agent: str = ""
    source_ip: str = ""
    read_only: bool | None = None
    error_code: str = ""
    category: str = "Management"   # Management | Data | Observation
    request: Any = field(default_factory=dict)
    response: Any = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @classmethod
    def from_cloudtrail(cls, rec: dict, account_id: str | None = None) -> "Event":
        ident = rec.get("userIdentity") or {}
        arn = ident.get("arn") or ""
        name = ident.get("userName") or ""
        key = ident.get("accessKeyId") or ""
        principal = arn or name or key or "unknown"
        short = (arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]) or name or key or "unknown"
        acct = str(rec.get("recipientAccountId") or ident.get("accountId") or account_id or "")
        if account_id:
            acct = str(account_id)   # the trail we read it from is the authority
        eid = rec.get("eventID") or hashlib.sha256(
            json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()[:32]
        ro = rec.get("readOnly")
        return cls(
            id=str(eid), time=parse_time(rec["eventTime"]), account_id=acct,
            service=str(rec.get("eventSource", "")), name=str(rec.get("eventName", "")),
            principal=principal, identity_name=short,
            user_agent=str(rec.get("userAgent") or ""), source_ip=str(rec.get("sourceIPAddress") or ""),
            read_only=ro if isinstance(ro, bool) else None,
            error_code=str(rec.get("errorCode") or ""),
            category="Data" if str(rec.get("eventCategory", "")).lower() == "data" else "Management",
            request=as_obj(rec.get("requestParameters")) or {},
            response=as_obj(rec.get("responseElements")) or {},
            raw=rec,
        )

    @classmethod
    def observation(cls, name: str, account_id: str, when: datetime, **facts: Any) -> "Event":
        """A synthetic event produced by polling state (not by an API call)."""
        rec = {"eventTime": iso(when), "eventName": name, "eventSource": "aegis.detector",
               "eventCategory": "Observation", "recipientAccountId": account_id,
               "requestParameters": facts, "eventID": f"obs-{name}-{account_id}-{int(when.timestamp())}"}
        ev = cls.from_cloudtrail(rec, account_id)
        ev.category = "Observation"
        ev.principal = ev.identity_name = "aegis-detector"
        return ev

    @property
    def succeeded(self) -> bool:
        return not self.error_code


@dataclass
class Detection:
    rule_id: str
    title: str
    description: str
    technique: str
    tactic: str
    severity: str                 # low | medium | high | critical
    account_id: str
    principal: str
    resource_type: str            # ASFF resource type, e.g. AwsS3Bucket
    resource_id: str
    event_time: datetime          # when the evidence event happened
    event_id: str
    event_name: str
    dedup_key: str = ""
    evidence: list = field(default_factory=list)   # event ids
    source: str = "python-engine"
    detected_at: datetime | None = None            # stamped by the engine when it emits

    @property
    def summary(self) -> str:
        return f"{self.title} ({self.event_name} by {self.principal.rsplit('/', 1)[-1]})"