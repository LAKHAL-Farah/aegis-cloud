"""Crash recovery for the responder (ADR-0018).

The ledger claims an incident BEFORE the human is asked. So a responder killed while a person is deciding leaves
a claim behind and, on restart, would call that finding "already handled" and drop it. The audit trail knows
better: an incident with a `received` record and no closing record was interrupted. This module finds those, and the
findings that arrived while the responder was down, and returns the files to handle again.
"""
from __future__ import annotations

import json
from pathlib import Path

from .incident import Incident

CLOSING = {"outcome", "skipped"}      # audit steps that end an incident's story


def classify(audit) -> tuple[set[str], set[str]]:
    """(closed, interrupted) incident short ids, from the audit trail."""
    received, closed, dup = set(), set(), set()
    for rec in audit.records():
        if rec["step"] == "received":
            received.add(rec["incident"])
        if rec["step"] in CLOSING:
            closed.add(rec["incident"])
        if rec["step"] == "duplicate":
            dup.add(rec["incident"])
    # A "duplicate" is final only for an incident that never started (a cooldown skip). For one that was interrupted
    # it just means a restart without --resume bumped into its old claim, which must not hide it.
    return closed | (dup - received), received - closed


def backlog(responder, findings_dir: Path, max_age_s: float | None = None) -> list[Path]:
    """Findings still owed a response. Interrupted incidents have their claim released first.
    max_age_s: ignore findings detected longer ago than this. After a long outage (or on first start with an old
    findings folder) chasing stale findings would flood a person with approvals for a world that has moved on."""
    closed, interrupted = classify(responder.audit)
    todo = []
    for path in sorted(Path(findings_dir).glob("*.json")):
        try:
            inc = Incident.from_asff(json.loads(path.read_text()))
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            continue                                  # not a finding: handle() would only reject it again
        if inc.short in closed:
            continue
        if max_age_s is not None and responder.clock() - inc.detected_at.timestamp() > max_age_s:
            continue
        if inc.short in interrupted:
            responder.ledger.release(inc.id)
            responder.audit.append(inc.short, "resumed", "ok", reason="interrupted before it finished; asking again")
        todo.append(path)
    return todo
