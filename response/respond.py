#!/usr/bin/env python3
"""AegisCloud responder CLI.

  respond.py watch   [--execute] [--approver file|telegram|auto]    follow build/findings and respond
  respond.py handle  FINDING.json [--execute] [--approver ...]       one finding
  respond.py pending                                                 approvals waiting for a person
  respond.py approve ID | deny ID                                    answer a file approval
  respond.py audit   [--incident ID]                                 show the trail and verify its chain
  respond.py rollback ID                                             re-activate keys this incident deactivated

Default is a DRY RUN: it plans, notifies and changes nothing. Add --execute to act, after approval.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aegis_respond.approval import FileApprover  # noqa: E402
from aegis_respond.audit import AuditLog  # noqa: E402
from aegis_respond.clients import is_local  # noqa: E402
from aegis_respond.config import build_approver, build_notifier  # noqa: E402
from aegis_respond.engine import Ledger, Responder  # noqa: E402
from aegis_respond.policy import ResponsePolicy  # noqa: E402
from aegis_respond.watch import watch  # noqa: E402

ROOT = HERE.parent
STATE = ROOT / "build" / "response"


def make_responder(args) -> Responder:
    endpoint = args.endpoint or os.environ.get("AEGIS_ENDPOINT") or None
    state = Path(args.state_dir)
    audit = AuditLog(state / "audit.jsonl")
    approver = build_approver(args.approver, state)
    if args.approver == "auto" and args.execute and not is_local(endpoint):
        sys.exit("refusing: --approver auto only works against LocalStack (set --endpoint http://localhost:4566)")
    return Responder(policy=ResponsePolicy.load(args.policy), approver=approver,
                     notifier=build_notifier(on_error=lambda n, e: audit.append("-", "notify", "error", channel=n, reason=e)),
                     audit=audit, ledger=Ledger(state / "ledger.json"), endpoint=endpoint, execute=args.execute)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state-dir", default=str(STATE))
    ap.add_argument("--policy", default=None)
    ap.add_argument("--endpoint", default=None, help="LocalStack URL; omit for real AWS (default credential chain)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--execute", action="store_true", help="act (after approval). Without it: plan only")
        p.add_argument("--approver", choices=["file", "telegram", "auto"], default="file")

    w = sub.add_parser("watch")
    common(w)
    w.add_argument("--findings-dir", default=str(ROOT / "build" / "findings"))
    w.add_argument("--replay", action="store_true", help="also handle findings already on disk")
    h = sub.add_parser("handle")
    common(h)
    h.add_argument("finding")
    sub.add_parser("pending")
    for name in ("approve", "deny"):
        sub.add_parser(name).add_argument("incident")
    a = sub.add_parser("audit")
    a.add_argument("--incident")
    r = sub.add_parser("rollback")
    r.add_argument("incident")
    r.add_argument("--execute", action="store_true")
    r.add_argument("--approver", default="file")
    args = ap.parse_args()
    state = Path(args.state_dir)

    if args.cmd == "pending":
        for p in FileApprover.pending(state / "approvals"):
            print(f"{p['incident_id']}  {p['severity']:8} {p['title']}\n" + "\n".join(f"    - {s}" for s in p["plan"]))
        return 0
    if args.cmd in ("approve", "deny"):
        try:
            FileApprover.decide(state / "approvals", args.incident, args.cmd == "approve", getpass.getuser())
        except FileNotFoundError as exc:
            print(exc, file=sys.stderr)
            return 1
        print(f"{args.cmd}d {args.incident}")
        return 0
    if args.cmd == "audit":
        log = AuditLog(state / "audit.jsonl")
        for rec in log.records(args.incident):
            print(f"{rec['seq']:4} {rec['ts']} {rec['incident']:12} {rec['step']:28} {rec['status']:8} "
                  f"{json.dumps(rec['data'])[:110]}")
        ok, msg = log.verify()
        print(("chain OK: " if ok else "CHAIN BROKEN: ") + msg)
        return 0 if ok else 2
    if args.cmd == "rollback":
        args.execute = True
        steps = make_responder(args).rollback(args.incident)
        for s in steps:
            print(("ok   " if s.ok else "FAIL ") + s.detail)
        return 0 if all(s.ok for s in steps) else 1

    responder = make_responder(args)
    mode = "EXECUTE (human approval required)" if args.execute else "DRY RUN (plans only)"
    if args.cmd == "handle":
        out = responder.handle(json.loads(Path(args.finding).read_text()))
        print(f"{out.status}: {out.detail}")
        return 0 if out.status in {"CONTAINED", "DRY_RUN", "NOOP", "SKIPPED"} else 1
    print(f"responder watching {args.findings_dir}  [{mode}, approver={args.approver}]  Ctrl-C to stop", flush=True)
    stop = threading.Event()
    try:
        watch(responder, Path(args.findings_dir), stop, replay=args.replay,
              on_outcome=lambda name, out: print(f"  {name}: {out.status} {out.detail}", flush=True))
    except KeyboardInterrupt:
        stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
