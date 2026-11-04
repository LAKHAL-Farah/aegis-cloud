#!/usr/bin/env python3
"""Stage 4 scored run: attack -> detect -> approve -> contain -> verify, with the clock running.

  make stage4-run LABEL=stage4-v1                      (starts the detector, runs this, stops the detector)
  python3 response/tools/measure.py --label stage4-v1 --approver auto

For each pair below it resets the range, runs the attack, waits for the responder to act on the finding the
detector raised, then checks the resulting state with ITS OWN admin client (not the responder's verify), and
restores the range. It writes docs/evidence/scorecards/<label>.json and .md.

Honesty switches
* --approver auto  approves instantly and the scorecard says "simulated approval". That measures the machines.
* --approver file|slack  includes a real person's reaction time. `machine_s` always excludes it.
* Only the purple twin is touched. The hardened twin exists to prevent, not to be remediated.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "response"))
sys.path.insert(0, str(ROOT / "cloudpurple"))

from aegis_respond.audit import AuditLog  # noqa: E402
from aegis_respond.clients import Clients, is_local  # noqa: E402
from aegis_respond.config import build_approver, build_notifier  # noqa: E402
from aegis_respond.engine import Ledger, Responder  # noqa: E402
from aegis_respond.policy import ResponsePolicy  # noqa: E402
from aegis_respond.watch import watch  # noqa: E402

TERMINAL = {"CONTAINED", "PARTIAL", "FAILED", "DENIED", "TIMEOUT", "NOOP", "REFUSED"}
# playbook id -> the Stage 2 scenario that provokes it. This file is the harness: it may know scenario ids.
PAIRS = [("leaked_key", "S11"), ("public_bucket", "S07")]
BPA_ALL_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---- the range, as the measurer sees it (admin clients, not the responder's)
class Range:
    def __init__(self, target: dict, endpoint: str):
        self.target, self.res, self.creds = target, target["resources"], target["credentials"]
        self.admin = Clients(target["account_id"], endpoint)

    @property
    def attacker_key(self) -> str:
        return self.creds["attacker_key_id"]

    def reset(self) -> None:
        """Back to the vulnerable starting state: attacker key active and alone, no replacement secret, bucket as built."""
        iam, sm = self.admin.get("iam"), self.admin.get("secretsmanager")
        for k in iam.list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]:
            if k["AccessKeyId"] != self.attacker_key:
                iam.delete_access_key(UserName="dev-svc", AccessKeyId=k["AccessKeyId"])
        iam.update_access_key(UserName="dev-svc", AccessKeyId=self.attacker_key, Status="Active")
        try:
            sm.delete_secret(SecretId=f"aegis/rotated-access-key/{self.target['account_id']}/dev-svc", ForceDeleteWithoutRecovery=True)
        except sm.exceptions.ResourceNotFoundException:
            pass

    def key_is_inactive(self) -> bool:
        keys = self.admin.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"]
        return any(k["AccessKeyId"] == self.attacker_key and k["Status"] == "Inactive" for k in keys)

    def bucket_is_private(self) -> bool:
        s3, bucket = self.admin.get("s3"), self.res["data_bucket"]
        try:
            bpa = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        except Exception:  # noqa: BLE001
            return False
        public = [g for g in s3.get_bucket_acl(Bucket=bucket).get("Grants", [])
                  if g.get("Grantee", {}).get("URI", "").rsplit("/", 1)[-1] in ("AllUsers", "AuthenticatedUsers")]
        return bpa == BPA_ALL_ON and not public

    def verify(self, playbook: str) -> bool:
        return self.key_is_inactive() if playbook == "leaked_key" else self.bucket_is_private()


# ---- pure logic (unit-tested)
def row_from(playbook: str, scenario: dict, t0: float, outcome, state_ok: bool | None, approver: str) -> dict:
    """One scorecard row from one measured pair. `outcome` is the Responder's Outcome or None (no response seen)."""
    row = {"playbook": playbook, "scenario": scenario["id"], "technique": scenario["technique"], "name": scenario["name"],
           "attack_start": iso(t0), "responded": outcome is not None, "approver": approver,
           "status": outcome.status if outcome else "NO_RESPONSE", "state_verified": state_ok}
    if outcome and outcome.incident:
        inc, tm = outcome.incident, outcome.timings()
        row.update(alert_rule=inc.rule, mttd_s=round(inc.detected_at.timestamp() - t0, 2),
                   human_wait_s=round(tm.get("human_wait_s", 0.0), 2))
        if "contained" in outcome.t and "detected_to_contained_s" in tm:
            row.update(attack_to_contained_s=round(outcome.t["contained"] - t0, 2),
                       detected_to_contained_s=round(tm["detected_to_contained_s"], 2),
                       machine_s=round(tm["machine_s"], 2))
        if outcome.t.get("verified"):
            row["attack_to_verified_s"] = round(outcome.t["verified"] - t0, 2)
    row["contained"] = bool(outcome and outcome.status == "CONTAINED" and state_ok)
    return row


def summarize(rows: list[dict]) -> dict:
    done = [r for r in rows if r["contained"]]
    mean = lambda key: (sum(r[key] for r in done if key in r) / len([r for r in done if key in r])) if any(key in r for r in done) else None  # noqa: E731
    return {"pairs": len(rows), "contained": len(done), "mean_attack_to_contained_s": mean("attack_to_contained_s"),
            "mean_machine_s": mean("machine_s"), "mean_mttd_s": mean("mttd_s"),
            "worst_attack_to_contained_s": max((r["attack_to_contained_s"] for r in done if "attack_to_contained_s" in r), default=None)}


def headline(s: dict, approver: str) -> str:
    f = lambda v: "-" if v is None else f"{v:.1f} s"  # noqa: E731
    mode = "simulated approval, 0 s human time" if approver == "auto" else "includes a real person's approval time"
    return (f"Contained and independently verified: {s['contained']} of {s['pairs']}  |  "
            f"attack to contained: mean {f(s['mean_attack_to_contained_s'])}, worst {f(s['worst_attack_to_contained_s'])}  |  "
            f"of which machine time: {f(s['mean_machine_s'])}  |  ({mode})")


def render_markdown(label: str, stamp: str, rows: list[dict], s: dict, approver: str) -> str:
    out = [f"# Response scorecard: {label}", "", f"_Generated {stamp}_", "", f"**{headline(s, approver)}**", ""]
    if approver == "auto":
        out += ["> The approval in this run was automated. The time to respond here is what the machines need; a person "
                "approving adds their own reaction time (see `human_wait_s` in a file or Slack run).", ""]
    out += ["| Playbook | Scenario | ATT&CK | Detected by | MTTD | Approval wait | Detected to contained | Attack to contained | Status | State verified |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    f = lambda v: "-" if v is None else f"{v:.1f} s"  # noqa: E731
    for r in rows:
        out.append(f"| {r['playbook']} | {r['scenario']} | {r['technique']} | {r.get('alert_rule', '-')} | {f(r.get('mttd_s'))} | "
                   f"{f(r.get('human_wait_s'))} | {f(r.get('detected_to_contained_s'))} | {f(r.get('attack_to_contained_s'))} | "
                   f"{r['status']} | {'yes' if r['state_verified'] else 'NO' if r['state_verified'] is False else '-'} |")
    out += ["", "## Notes", "",
            "* `Attack to contained` runs from the first API call of the attack to the moment containment finished.",
            "* `State verified` is checked by the measurer's own admin client after the responder finished: the responder's own "
            "verify step is not taken on trust.",
            "* The range is restored after each pair, so one pair's containment never affects the next attack."]
    return "\n".join(out) + "\n"


# ---- orchestration
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", required=True)
    ap.add_argument("--approver", choices=["auto", "file", "slack"], default="auto")
    ap.add_argument("--only", help="comma-separated playbook ids")
    ap.add_argument("--timeout", type=int, default=150, help="seconds to wait for a response per pair")
    ap.add_argument("--endpoint", default="http://localhost:4566")
    ap.add_argument("--findings-dir", default=str(ROOT / "build" / "findings"))
    args = ap.parse_args()

    if not is_local(args.endpoint):
        print("refusing: this tool performs real attack calls and must only target LocalStack", file=sys.stderr)
        return 2
    out_json = ROOT / "docs" / "evidence" / "scorecards" / f"{args.label}.json"
    if out_json.exists():
        print(f"{out_json.name} exists: scorecards are evidence and are never overwritten", file=sys.stderr)
        return 1
    tpath = ROOT / "build" / "range" / "targets.json"
    if not tpath.exists():
        print("no build/range/targets.json: run `make range-up` first", file=sys.stderr)
        return 1

    from attacks import scenarios as _s  # noqa: F401,E402  (fills the registry)
    from attacks.context import Context, Target
    from attacks.scenario import REGISTRY

    purple = json.loads(tpath.read_text())["purple"]
    rng = Range(purple, args.endpoint)
    state = ROOT / "build" / "response" / f"measure-{args.label}"
    audit = AuditLog(state / "audit.jsonl")
    approver = build_approver(args.approver, state)
    responder = Responder(policy=ResponsePolicy.load(), approver=approver, notifier=build_notifier(), audit=audit,
                          ledger=Ledger(state / "ledger.json"), endpoint=args.endpoint, execute=True)

    outcomes: list = []
    lock = threading.Lock()
    stop = threading.Event()
    started = time.time()

    def record(_name, outcome):
        with lock:
            outcomes.append(outcome)

    th = threading.Thread(target=watch, args=(responder, Path(args.findings_dir), stop),
                          kwargs={"since": started - 1, "poll_s": 0.2, "on_outcome": record},
                          daemon=True)
    th.start()

    pairs = [p for p in PAIRS if not args.only or p[0] in args.only.split(",")]
    rows = []
    print(f"Stage 4 run '{args.label}' on purple={purple['account_id']}  approver={args.approver}\n")
    try:
        for playbook, sid in pairs:
            sc = REGISTRY[sid]
            rng.reset()
            sc.cleanup(Context(Target(purple["name"], purple["account_id"], False, purple["resources"], purple["credentials"]),
                               args.endpoint, "us-east-1", run_id=f"s4-{sid}"))
            ctx = Context(Target(purple["name"], purple["account_id"], False, purple["resources"], purple["credentials"]),
                          args.endpoint, "us-east-1", run_id=f"s4-{sid}")
            print(f"[{playbook}] attack {sid} {sc.name} ...", end=" ", flush=True)
            t0 = time.time()
            sc.run(ctx)
            t1 = time.time()
            got = None
            while time.time() - t1 < args.timeout and got is None:
                with lock:
                    got = next((o for o in outcomes if o.playbook == playbook and o.status in TERMINAL and o.incident
                                and t0 - 2 <= o.incident.event_time.timestamp() <= t1 + 2), None)
                time.sleep(0.2)
            ok = rng.verify(playbook) if got else None
            rows.append(row_from(playbook, {"id": sid, "technique": sc.technique, "name": sc.name}, t0, got, ok, args.approver))
            print(f"{rows[-1]['status']}  attack-to-contained={rows[-1].get('attack_to_contained_s', '-')} s  verified={ok}")
            rng.reset()
            sc.cleanup(ctx)
    finally:
        stop.set()
        th.join(5)
        rng.reset()

    summary = summarize(rows)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta = {"purple_account": purple["account_id"], "approver": args.approver, "endpoint": args.endpoint,
            "audit_chain": audit.verify()[1], "note": "approval simulated" if args.approver == "auto" else "real approval"}
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps({"label": args.label, "generated": stamp, "summary": summary, "meta": meta, "rows": rows}, indent=2))
    out_json.with_suffix(".md").write_text(render_markdown(args.label, stamp, rows, summary, args.approver))
    print("\n" + headline(summary, args.approver) + f"\nwrote {out_json} and .md")
    return 0 if summary["contained"] == summary["pairs"] else 1


if __name__ == "__main__":
    sys.exit(main())
