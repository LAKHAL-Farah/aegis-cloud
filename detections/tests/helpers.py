"""Builders for synthetic CloudTrail records. Shapes follow real CloudTrail; LocalStack's own shapes are
checked separately by `make detect-probe`, which is why these tests say nothing about LocalStack."""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
ACCT = "555555555555"
_ids = itertools.count(1)


def user_arn(name: str, acct: str = ACCT) -> str:
    return f"arn:aws:iam::{acct}:{'root' if name == 'root' else 'user/' + name}"


def rec(name: str, service: str, *, who: str = "dev-svc", at: float = 0.0, req=None, ua: str = "Boto3/1.34.0 Botocore/1.34.0",
        category: str = "Management", read_only: bool | None = None, error: str | None = None, acct: str = ACCT) -> dict:
    out = {
        "eventVersion": "1.09", "eventTime": (T0 + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": f"{service}.amazonaws.com", "eventName": name, "awsRegion": "us-east-1",
        "sourceIPAddress": "172.17.0.1", "userAgent": ua, "eventID": f"evt-{next(_ids):06d}",
        "eventCategory": category, "recipientAccountId": acct,
        "userIdentity": {"type": "IAMUser", "arn": user_arn(who, acct), "accountId": acct, "userName": who,
                         "accessKeyId": "AKIAEXAMPLE"},
        "requestParameters": req or {},
    }
    if read_only is not None:
        out["readOnly"] = read_only
    if error:
        out["errorCode"] = error
    return out