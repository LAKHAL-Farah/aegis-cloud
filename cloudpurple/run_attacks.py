#!/usr/bin/env python3
"""THE command. Runs every scenario against both twins and prints the scorecard.

Usage:
  make attack LABEL=baseline
  python3 cloudpurple/run_attacks.py --label stage3-v1 --settle 25
  python3 cloudpurple/run_attacks.py --rescore stage3-v1 --label stage3-v1-late   (no attacks, re-reads alerts)
  python3 cloudpurple/run_attacks.py --only S04,S09 --as-root
  python3 cloudpurple/run_attacks.py --list
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from attacks import scenarios as _load_scenarios  # noqa: F401  (populates the registry)
from attacks.attribution import attribute_alerts
from attacks.context import Context, Target
from attacks.detection import load_alerts, telemetry_status
from attacks.scenario import all_scenarios
from attacks.scoring import (DENIED, ERROR, SUCCEEDED, headline, is_denied, load_known_limits, prevented_by,
                             render_markdown, summarize)

ROOT = HERE.parent
ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
ALERT_WINDOW_SECONDS = 120
SETTLE_SECONDS = 20

def _guard_endpoint(endpoint: str) -> None:
    host = (urlparse(endpoint).hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "localstack", "localstack.localhost"}:
        print(f"refusing to run: endpoint '{endpoint}' is not LocalStack. "
              "This runner performs real attack API calls and must never target a real AWS account.",
              file=sys.stderr)
        sys.exit(2)

def load_targets() -> dict:
    path = ROOT / "build" / "range" / "targets.json"
    if not path.exists():
        print("no build/range/targets.json: run `make range-up` first", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def run_one(sc, target_data: dict, run_id: str, as_root: bool) -> dict:
    t = Target(target_data["name"], target_data["account_id"], target_data["hardened"],
               target_data["resources"], target_data["credentials"])
    ctx = Context(t, ENDPOINT, "us-east-1", run_id=f"{run_id}-{sc.id}", as_root=as_root)

    t0 = datetime.now(timezone.utc)
    result = {"outcome": None, "detail": None}
    try:
        detail = sc.run(ctx) or {}
        result["outcome"] = SUCCEEDED
        result["detail"] = detail.get("detail", "")
    except Exception as exc:  # noqa: BLE001 - classify whatever comes back
        if is_denied(exc):
            result["outcome"] = DENIED
            msg = str(getattr(exc, "response", {}).get("Error", {}).get("Message", exc))
            result["detail"] = msg
            result["prevented_by"] = prevented_by(msg)
        else:
            result["outcome"] = ERROR
            result["detail"] = str(exc)

    telemetry = "-"
    if not t.hardened and result["outcome"] == SUCCEEDED:
        if sc.data_events:
            telemetry = "DATA-EVENT (lookup-events cannot see it; check the trail's S3 destination manually)"
        else:
            ct = ctx.admin("cloudtrail")
            status, _found = telemetry_status(ct, sc.expected_events, t0) if sc.expected_events else ("N/A", [])
            telemetry = status
    result["telemetry"] = telemetry

    try:
        sc.cleanup(ctx)
    except Exception as exc:  # noqa: BLE001 - cleanup must never crash the run
        print(f"  [{sc.id}/{t.name}] cleanup warning: {exc}", file=sys.stderr)

    return {"side": result, "t0": t0}

def write_scorecard(label: str, run_id: str, rows: list[dict], extras: dict, meta: dict) -> None:
    known = load_known_limits()
    summary = summarize(rows, known)
    summary.update(extras)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out_dir = ROOT / "docs" / "evidence" / "scorecards"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{label}.json").write_text(json.dumps(
        {"label": label, "run_id": run_id, "generated": stamp, "summary": summary, "meta": meta, "rows": rows}, indent=2))
    (out_dir / f"{label}.md").write_text(render_markdown(label, stamp, rows, summary, known))
    print(f"\n{headline(summary)}")
    print(f"wrote {out_dir}/{label}.md and {label}.json")

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--label", default="run", help="name for this run, e.g. baseline")
    ap.add_argument("--only", help="comma-separated scenario IDs, e.g. S04,S09")
    ap.add_argument("--as-root", action="store_true",
                    help="act as the account root instead of the stolen dev-svc key (isolates SCP effects from IAM-boundary effects)")
    ap.add_argument("--alert-dir", default=str(ROOT / "build" / "alerts"))
    ap.add_argument("--window", type=int, default=ALERT_WINDOW_SECONDS, help="max seconds from attack start to alert")
    ap.add_argument("--settle", type=int, default=SETTLE_SECONDS,
                    help="seconds to wait after the last scenario so slow detectors can finish (Stage 3)")
    ap.add_argument("--slop", type=float, default=1.0, help="clock tolerance in seconds between host and LocalStack")
    ap.add_argument("--alert-source", default=None, help="only credit alerts from this detector, e.g. python-engine")
    ap.add_argument("--rescore", metavar="LABEL", help="re-score a saved scorecard against the alerts now on disk (no attacks)")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    args = ap.parse_args()

    scs = all_scenarios()
    if args.list:
        for sc in scs:
            print(f"{sc.id}  {sc.technique:10}  {sc.tactic:20}  {sc.name}")
        return 0

    alert_dir = Path(args.alert_dir)

    if args.rescore:
        src = ROOT / "docs" / "evidence" / "scorecards" / f"{args.rescore}.json"
        if not src.exists():
            print(f"no saved scorecard {src}", file=sys.stderr)
            return 1
        if args.label in ("run", args.rescore):
            print("give --label a new name: saved scorecards are evidence and are never overwritten", file=sys.stderr)
            return 1
        saved = json.loads(src.read_text())
        rows = saved["rows"]
        if not all("attack_start" in r for r in rows):
            print(f"{args.rescore} has no attack_start/attack_end (it predates Stage 3): it cannot be re-scored", file=sys.stderr)
            return 1
        account = saved["meta"]["purple_account"]
        extras = attribute_alerts(rows, load_alerts(alert_dir), account, args.window, args.slop, args.alert_source)
        write_scorecard(args.label, saved["run_id"], rows, extras, {**saved["meta"], "rescored_from": args.rescore})
        return 0

    _guard_endpoint(ENDPOINT)
    if args.only:
        wanted = set(args.only.split(","))
        scs = [s for s in scs if s.id in wanted]
        if not scs:
            print(f"no scenario matches --only {args.only}", file=sys.stderr)
            return 1

    targets = load_targets()
    run_id = uuid.uuid4().hex[:8]
    rows = []
    print(f"CloudPurple attack run '{args.label}' ({run_id}) against purple={targets['purple']['account_id']} "
          f"hardened={targets['hardened']['account_id']}{'  [as account root]' if args.as_root else ''}\n")

    for sc in scs:
        print(f"[{sc.id}] {sc.name} ({sc.technique}) ...", end=" ", flush=True)
        purple = run_one(sc, targets["purple"], run_id, args.as_root)
        hardened = run_one(sc, targets["hardened"], run_id, args.as_root)
        t_end = datetime.now(timezone.utc)
        print(f"purple={purple['side']['outcome']} hardened={hardened['side']['outcome']}")
        rows.append({
            "id": sc.id, "name": sc.name, "technique": sc.technique, "tactic": sc.tactic,
            "purple": purple["side"], "hardened": hardened["side"],
            "attack_start": _iso(purple["t0"]), "attack_end": _iso(t_end),
        })

    # Stage 3: score once, after the detectors have had time to finish (the Stage 2 loop looked after 1 s).
    if args.settle > 0:
        print(f"\nsettling {args.settle} s so detectors can finish ...", flush=True)
        time.sleep(args.settle)
    extras = attribute_alerts(rows, load_alerts(alert_dir), targets["purple"]["account_id"],
                              args.window, args.slop, args.alert_source)
    meta = {"purple_account": targets["purple"]["account_id"], "hardened_account": targets["hardened"]["account_id"],
            "window_s": args.window, "settle_s": args.settle, "as_root": args.as_root,
            "alert_source": args.alert_source}
    write_scorecard(args.label, run_id, rows, extras, meta)
    return 0

if __name__ == "__main__":
    sys.exit(main())