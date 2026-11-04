"""AWS Lambda entry point. EventBridge delivers the ASFF finding in `detail` (detections/aegis_detect/sinks.py,
EventBridgeSink). The Lambda never asks a human itself: it acts only when the event carries an approval that is
signed for THIS finding and has not expired (approval.sign_approval). Anyone who can put events on the bus can
forge an unsigned approval, so the signature is what the authority rests on, not the bus.

    {"detail": {<ASFF finding>}, "approval": {"approved_by": "farah", "expires": 1760000000, "signature": "<hex>"}}
"""
from __future__ import annotations

import os
from pathlib import Path

from .approval import verify_approval
from .audit import AuditLog
from .config import build_notifier
from .engine import Ledger, Responder
from .policy import ResponsePolicy

STATE = Path(os.environ.get("AEGIS_STATE_DIR", "/tmp/aegis-respond"))


class _NeverAsks:
    name = "signed-event"

    def request(self, inc, plan, timeout_s):  # pragma: no cover - the decision always arrives pre-made
        raise RuntimeError("the Lambda path does not ask: it needs a signed approval in the event")


def handler(event: dict, context=None) -> dict:
    finding = (event or {}).get("detail") or {}
    key = os.environ.get("AEG_APPROVAL_HMAC_KEY", "").encode()
    decision = verify_approval(key, str(finding.get("Id", "")), (event or {}).get("approval"))
    responder = Responder(
        policy=ResponsePolicy.load(), approver=_NeverAsks(), notifier=build_notifier(),
        audit=AuditLog(STATE / "audit.jsonl", mirror=print), ledger=Ledger(STATE / "ledger.json"),
        endpoint=os.environ.get("AEGIS_ENDPOINT") or None, region=os.environ.get("AWS_REGION", "us-east-1"),
        execute=True)
    out = responder.handle(finding, presented_decision=decision)
    return {"status": out.status, "detail": out.detail, "timings": {k: round(v, 3) for k, v in out.timings().items()}}
