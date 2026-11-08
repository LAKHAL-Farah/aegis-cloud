"""The Responder: finding -> match -> plan (read-only) -> human approval -> contain -> verify -> audit + notify.

Rules of the house
* Nothing changes before a human says yes, and a missing answer is a no.
* The plan the human approved is the plan that runs. contain() gets that exact object.
* Protected identities (root, break-glass, the responder itself) are never touched, approved or not.
* Every step lands in the hash-chained audit trail before the next one starts.
* The same incident, or the same principal inside the cooldown, is handled once."""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from .approval import AutoApprover, Decision
from .advice import HEADER
from .advice import tag as tag_advice
from .audit import AuditLog
from .clients import Clients, is_local
from .incident import SEVERITY_ORDER, Incident
from .playbooks import PLAYBOOKS, PlaybookRefusal
from .policy import ResponsePolicy

CONTAINED, PARTIAL, FAILED, DENIED, TIMEOUT = "CONTAINED", "PARTIAL", "FAILED", "DENIED", "TIMEOUT"
DRY_RUN, SKIPPED, REFUSED, DUPLICATE, NOOP, REJECTED = "DRY_RUN", "SKIPPED", "REFUSED", "DUPLICATE", "NOOP", "REJECTED"


@dataclass
class Outcome:
    status: str
    detail: str = ""
    incident: Incident | None = None
    playbook: str = ""
    decision: Decision | None = None
    steps: list = field(default_factory=list)
    t: dict = field(default_factory=dict)        # epoch seconds: received, approval_asked, approved, contained, verified

    def timings(self) -> dict:
        """Everything derived from the stamps. `machine_s` is the response with the human's thinking time removed."""
        out: dict = {}
        t, inc = self.t, self.incident
        human = self.decision.waited_s if self.decision else 0.0
        if "contained" in t and inc:
            out["event_to_contained_s"] = t["contained"] - inc.event_time.timestamp()
            out["detected_to_contained_s"] = t["contained"] - inc.detected_at.timestamp()
            out["human_wait_s"] = human
            out["machine_s"] = out["detected_to_contained_s"] - human
        if "verified" in t and inc:
            out["event_to_verified_s"] = t["verified"] - inc.event_time.timestamp()
        return out


class Ledger:
    """Remembers what was handled, on disk, so a restart does not re-ask yesterday's questions."""

    def __init__(self, path: Path):
        self.path, self._lock = Path(path), threading.Lock()
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {"incidents": {}, "principals": {}}

    def claim(self, incident_id: str, key: str, now: float, cooldown_s: float) -> str | None:
        with self._lock:
            if incident_id in self.data["incidents"]:
                return "this finding was already handled"
            last = self.data["principals"].get(key)
            if last is not None and now - last < cooldown_s:
                return f"{key.split('|', 1)[1]} was handled {now - last:.0f} s ago (cooldown {cooldown_s:.0f} s)"
            self.data["incidents"][incident_id] = now
            self.data["principals"][key] = now
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data))
            return None


    def release(self, incident_id: str) -> bool:
        """Forget a claim, so an incident that was interrupted before it finished can be handled again.
        Removes the principal cooldown written by the same claim (same timestamp), never anyone else's."""
        with self._lock:
            claimed = self.data["incidents"].pop(incident_id, None)
            if claimed is None:
                return False
            for key in [k for k, v in self.data["principals"].items() if v == claimed]:
                del self.data["principals"][key]
            self.path.write_text(json.dumps(self.data))
            return True


class Responder:
    def __init__(self, *, policy: ResponsePolicy, approver, notifier, audit: AuditLog, ledger: Ledger,
                 endpoint: str | None = None, region: str = "us-east-1", execute: bool = False,
                 playbooks: dict | None = None, clock=time.time, clients_factory=None, advisor=None):
        if isinstance(approver, AutoApprover) and execute and not is_local(endpoint):
            raise ValueError("AutoApprover is only allowed against LocalStack: a person must approve on real AWS")
        self.policy, self.approver, self.notifier, self.audit, self.ledger = policy, approver, notifier, audit, ledger
        self.endpoint, self.region, self.execute, self.clock = endpoint, region, execute, clock
        self.playbooks = playbooks if playbooks is not None else PLAYBOOKS
        self.advisor = advisor          # optional, display only (ADR-0020): lines shown to the approver, never part of the plan
        self._clients = clients_factory or (lambda acct: Clients(acct, endpoint, region))

    # -- helpers
    def _say(self, inc: Incident | None, text: str) -> None:
        try:
            self.notifier.send(text, inc.public() if inc else None)
        except Exception as exc:  # noqa: BLE001 - a dead chat must never stop containment
            self.audit.append(inc.short if inc else "-", "notify", "error", reason=type(exc).__name__)

    def _finish(self, out: Outcome, inc: Incident | None, text: str | None = None) -> Outcome:
        self.audit.append(inc.short if inc else "-", "outcome", out.status.lower(), detail=out.detail,
                          timings={k: round(v, 3) for k, v in out.timings().items()})
        if text:
            self._say(inc, text)
        return out

    def _advice(self, inc: Incident, summary: list) -> list:
        """Advisory lines for the person approving. Fails open: advice that errors is dropped, containment never waits for it."""
        if not self.advisor:
            return []
        try:
            lines = [tag_advice(x) for x in self.advisor(inc, list(summary))][:6]
        except Exception as exc:  # noqa: BLE001
            self.audit.append(inc.short, "advice", "error", reason=type(exc).__name__)
            return []
        if lines:
            self.audit.append(inc.short, "advice", "ok", lines=lines)
        return lines

    def match(self, inc: Incident):
        return next((p for p in self.playbooks.values() if p.matches(inc, self.policy)), None)

    # -- the flow
    def handle(self, finding: dict, presented_decision: Decision | None = None) -> Outcome:
        t = {"received": self.clock()}
        try:
            inc = Incident.from_asff(finding)
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            self.audit.append("-", "rejected", "error", reason=str(exc))
            return Outcome(REJECTED, str(exc), t=t)

        if inc.severity_rank < SEVERITY_ORDER.get(self.policy.min_severity, 2):
            self.audit.append(inc.short, "skipped", "ok", reason=f"severity {inc.severity} is below {self.policy.min_severity}")
            return Outcome(SKIPPED, "below minimum severity", inc, t=t)
        pb = self.match(inc)
        if not pb:
            self.audit.append(inc.short, "skipped", "ok", reason=f"no enabled playbook for rule {inc.rule}")
            return Outcome(SKIPPED, f"no playbook for {inc.rule}", inc, t=t)
        out = Outcome(SKIPPED, "", inc, pb.id, t=t)

        if self.policy.is_protected(inc.identity):
            out.status, out.detail = REFUSED, f"{inc.identity} is a protected identity"
            self.audit.append(inc.short, "refused", "ok", reason=out.detail, **inc.public())
            return self._finish(out, inc, f"AegisCloud: {inc.title}\nNot touching protected identity {inc.identity}. A person must handle this.")

        if self.execute:
            why = self.ledger.claim(inc.id, f"{pb.id}|{inc.principal or inc.resource_id}", t["received"], self.policy.cooldown_s)
            if why:
                self.audit.append(inc.short, "duplicate", "ok", reason=why)
                return Outcome(DUPLICATE, why, inc, pb.id, t=t)

        self.audit.append(inc.short, "received", "ok", playbook=pb.id, **inc.public())
        clients = self._clients(inc.account_id)
        try:
            plan = pb.plan(inc, clients, self.policy)
        except PlaybookRefusal as exc:
            out.status, out.detail = REFUSED, str(exc)
            self.audit.append(inc.short, "refused", "ok", reason=str(exc))
            return self._finish(out, inc, f"AegisCloud: {inc.title}\nPlaybook {pb.id} declined: {exc}")
        except (ClientError, BotoCoreError) as exc:
            out.status, out.detail = FAILED, f"could not read state: {type(exc).__name__}"
            return self._finish(out, inc, f"AegisCloud: {inc.title}\nCould not read the current state ({type(exc).__name__}). Nothing was changed.")
        self.audit.append(inc.short, "plan", "ok", facts=plan.facts, summary=plan.summary)

        if not plan.actionable:
            out.status, out.detail = NOOP, plan.summary[0]
            return self._finish(out, inc, f"AegisCloud: {inc.title}\n{plan.summary[0]}")
        advice = self._advice(inc, plan.summary)
        if not self.execute:
            out.status, out.detail = DRY_RUN, "plan only (run with --execute to act)"
            return self._finish(out, inc, f"[dry run] {inc.title}\n" + "\n".join(f"- {s}" for s in plan.summary)
                                + (f"\n{HEADER}:\n" + "\n".join(advice) if advice else ""))

        self._say(inc, f"AegisCloud {inc.severity.upper()}: {inc.title}\nWaiting for approval of {len(plan.targets['actions'])} action(s).")
        t["approval_asked"] = self.clock()
        if presented_decision is not None:
            decision = presented_decision
        else:
            try:
                decision = self.approver.request(inc, plan.summary + advice, self.policy.approval_timeout_s)
            except Exception as exc:  # noqa: BLE001 - fail closed
                decision = Decision(False, "error", f"approval channel failed: {type(exc).__name__}")
        t["approved"] = self.clock()
        out.decision = decision
        self.audit.append(inc.short, "approval", "ok" if decision.approved else "denied", by=decision.by,
                          reason=decision.reason, automated=decision.automated, waited_s=round(decision.waited_s, 3))
        if not decision.approved:
            out.status = TIMEOUT if decision.by == "timeout" else DENIED
            out.detail = decision.reason
            return self._finish(out, inc, f"AegisCloud: {inc.title}\nNo action taken: {decision.reason}.")

        steps = pb.contain(inc, clients, plan, self.policy)
        t["contained"] = self.clock()
        out.steps = steps
        for s in steps:
            self.audit.append(inc.short, s.name, "ok" if s.ok else "error", detail=s.detail, **s.data)
        try:
            ver = pb.verify(inc, clients, plan)
        except (ClientError, BotoCoreError) as exc:
            from .playbooks import Step
            ver = Step("verify", False, f"could not verify: {type(exc).__name__}")
        t["verified"] = self.clock()
        self.audit.append(inc.short, "verify", "ok" if ver.ok else "error", detail=ver.detail)

        all_ok = bool(steps) and all(s.ok for s in steps)
        out.status = CONTAINED if (all_ok and ver.ok) else PARTIAL if any(s.ok for s in steps) else FAILED
        out.detail = ver.detail
        head = {CONTAINED: "Contained", PARTIAL: "PARTIALLY contained, needs a person", FAILED: "FAILED, needs a person"}[out.status]
        return self._finish(out, inc, f"AegisCloud: {head}: {inc.title}\n" + "\n".join(f"- {s.detail}" for s in steps) +
                            f"\n- verify: {ver.detail}\nEvent to contained: {out.timings().get('event_to_contained_s', 0):.1f} s "
                            f"(of which approval wait {decision.waited_s:.1f} s)")

    def rollback(self, incident_short: str) -> list:
        records = self.audit.records(incident_short)
        pb_id = next((r["data"].get("playbook") for r in records if r["step"] == "received"), None)
        acct = next((r["data"].get("account_id") for r in records if r["step"] == "received"), None)
        if not pb_id or not acct or pb_id not in self.playbooks:
            raise KeyError(f"no recorded incident {incident_short}")
        steps = self.playbooks[pb_id].rollback(self._clients(acct), records)
        for s in steps:
            self.audit.append(incident_short, s.name, "ok" if s.ok else "error", detail=s.detail)
        self._say(None, f"AegisCloud: rollback of {incident_short}: " + "; ".join(s.detail for s in steps))
        return steps
