#!/usr/bin/env python3
"""IAM Sentinel CLI. Read-only: it reads IAM and CloudTrail, it never changes anything.

  sentinel.py collect  [--endpoint URL] [--account ID] [--out FILE]     snapshot of one account
  sentinel.py scan     SNAPSHOT... [--scp FILE...] [--write]            escalation paths, standing admins, findings
  sentinel.py trail    [--endpoint URL] [--account ID] [--out FILE]     recent CloudTrail events (lookup-events) as JSON
  sentinel.py leastpriv --snapshot S --trail PATH [--principal NAME]    policy from observed usage, with its checks
  sentinel.py cypher   SNAPSHOT                                         Neo4j import script on stdout
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from aegis_sentinel import cypher, escalation, findings, leastpriv, snapshot  # noqa: E402
from aegis_sentinel.actions import Universe  # noqa: E402
from aegis_sentinel.iam_eval import statements  # noqa: E402

OUT = HERE.parent / "build" / "sentinel"


def aws_config():
    from botocore.config import Config
    return Config(retries={"max_attempts": 2}, connect_timeout=5, read_timeout=60)    # a dead endpoint should fail in seconds


def load_denies(paths) -> list:
    """Plain Deny statements from SCP JSON files, applied to every principal. Statements with a Condition are kept
    as conditional and therefore never remove a path (iam_eval)."""
    out = []
    for p in paths or []:
        out += [s for s in statements(json.loads(Path(p).read_text()), Path(p).stem) if s.effect == "Deny"]
    return out


def read_trail(path: str) -> list[dict]:
    recs = []
    files = sorted(Path(path).rglob("*.json*")) if Path(path).is_dir() else [Path(path)]
    for f in files:
        text = f.read_text()
        try:
            data = json.loads(text)
            recs += data.get("Records", []) if isinstance(data, dict) else data
        except ValueError:
            recs += [json.loads(line) for line in text.splitlines() if line.strip()]
    return recs


def cmd_collect(a) -> int:
    import boto3
    acct = a.account or os.environ.get("AWS_ACCESS_KEY_ID", "")
    kw = {"endpoint_url": a.endpoint} if a.endpoint else {}
    try:
        iam = boto3.client("iam", region_name="us-east-1", config=aws_config(), **kw)
        if not a.account:
            acct = boto3.client("sts", region_name="us-east-1", config=aws_config(), **kw).get_caller_identity()["Account"]
        snap = snapshot.collect(iam, acct)
    except Exception as exc:  # noqa: BLE001 - one unreachable account must not hide the others
        print(f"{acct or '?'}: could not collect ({type(exc).__name__}: {str(exc)[:160]}). Is LocalStack up at {a.endpoint or 'the default endpoint'}?",
              file=sys.stderr)
        return 1
    out = Path(a.out or OUT / f"snapshot-{acct}.json")
    snapshot.save(snap, out)
    print(f"{acct}: {sum(1 for p in snap['principals'].values() if p['kind'] != 'group')} users and roles, "
          f"{len(snap['policies'])} policies, {len(snap['unresolved'])} unresolved -> {out}")
    for w in snap.get("warnings", []):
        print("  warning:", w)
    return 0


def fetch_trail(ct, max_events: int = 5000) -> list[dict]:
    """CloudTrail LookupEvents, newest first. Each event carries the full record as a JSON string."""
    recs = []
    for page in ct.get_paginator("lookup_events").paginate(PaginationConfig={"MaxItems": max_events}):
        for ev in page.get("Events", []):
            try:
                recs.append(json.loads(ev["CloudTrailEvent"]))
            except (KeyError, ValueError):
                continue
    return recs


def cmd_trail(a) -> int:
    import boto3
    kw = {"endpoint_url": a.endpoint} if a.endpoint else {}
    recs = fetch_trail(boto3.client("cloudtrail", region_name="us-east-1", config=aws_config(), **kw))
    out = Path(a.out or OUT / "trail.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"Records": recs}))
    print(f"{len(recs)} events -> {out}")
    return 0


def render(result: dict) -> str:
    s = result["summary"]
    lines = [f"account {result['account_id']}: {s['escalates']} escalate, {s['admin']} standing admin, "
             f"{s['expected_admin']} expected admin, {s['capped']} capped by a boundary, {s['ordinary']} ordinary"]
    for arn, p in sorted(result["principals"].items(), key=lambda kv: (kv[1]["category"], kv[1]["name"])):
        if p["category"] == "ordinary":
            continue
        lines.append(f"  {p['category']:15} {p['kind']:5} {p['name']}")
        for step in p["path"]:
            cond = " (conditional)" if step["conditional"] else ""
            lines.append(f"      -> {step['to']:12} {step['technique']:7} {step['label']}{cond}  [{step['attack']}]")
        if p["category"] == "capped":
            lines.append(f"      the boundary caps: {', '.join(p['capped'])}")
    if result["unresolved"]:
        lines.append(f"  NOT ANALYSED: {len(result['unresolved'])} attached policies could not be read: they count as no permissions. "
                     + ", ".join(result["unresolved"][:3]))
    if result["approximate"]:
        lines.append(f"  approximate: {', '.join(a.rsplit('/', 1)[-1] for a in result['approximate'])} come from a bundled table")
    return "\n".join(lines)


def cmd_scan(a) -> int:
    denies, policy = load_denies(a.scp), escalation.load_policy(a.policy)
    results = [escalation.scan(snapshot.load(p), policy, denies) for p in a.snapshots]
    for r in results:
        print(render(r))
    if a.write:
        OUT.mkdir(parents=True, exist_ok=True)
        merged = {"schema": "aegis.sentinel-scan/v1", "generated": snapshot._now(), "accounts": {r["account_id"]: r for r in results}}
        (OUT / "scan.json").write_text(json.dumps(merged, indent=2, sort_keys=True))
        fdir = OUT / "findings"
        fdir.mkdir(exist_ok=True)
        n = 0
        for r in results:
            for f in findings.to_asff(r):
                (fdir / (f["Id"].replace("/", "_") + ".json")).write_text(json.dumps(f, indent=2))
                n += 1
        print(f"wrote {OUT / 'scan.json'} and {n} posture finding(s) in {fdir} (not build/findings: they are not incidents)")
    return 1 if a.fail_on_path and any(r["summary"]["escalates"] or r["summary"]["admin"] for r in results) else 0


def describe_identities(records: list[dict]) -> str:
    """What kinds of caller the trail holds, so an empty result can be explained instead of guessed at."""
    kinds: dict[str, int] = {}
    for r in records:
        ident = r.get("userIdentity") or {}
        key = f"{ident.get('type', 'no type')}{'' if ident.get('arn') else ' (no arn)'}"
        kinds[key] = kinds.get(key, 0) + 1
    return ", ".join(f"{k}: {v}" for k, v in sorted(kinds.items(), key=lambda kv: -kv[1])) or "no events"


def cmd_leastpriv(a) -> int:
    snap = snapshot.load(a.snapshot)
    records = read_trail(a.trail)
    usage = leastpriv.usage_from_cloudtrail(records, snap)
    wanted = {u.name: u for u in usage.values()}
    if a.principal:
        if a.principal not in wanted:
            print(f"no usable events for {a.principal}; principals with events: {', '.join(sorted(wanted)) or 'nobody'}.\n"
                  f"  the {len(records)} events in the trail are from: {describe_identities(records)}.\n"
                  f"  A principal only appears after it has acted: run the activity first (for example `make attack`), then ask again.",
                  file=sys.stderr)
            return 1
        wanted = {a.principal: wanted[a.principal]}
    uni, denies, policy = Universe(), load_denies(a.scp), escalation.load_policy(a.policy)
    OUT.mkdir(parents=True, exist_ok=True)
    for name, u in sorted(wanted.items()):
        if u.arn not in snap["principals"]:
            print(f"{name}: not in the snapshot, skipped")
            continue
        r = leastpriv.analyse(snap, u, uni, policy, a.keep_sensitive, denies)
        path = Path(a.out_dir or OUT) / f"leastpriv-{name}.json"
        path.write_text(json.dumps(r, indent=2, sort_keys=True))
        n = r["notes"]
        print(f"{name}: granted {r['granted_before']} -> {r['granted_after']} actions ({r['reduction_pct']}% fewer; wildcard sized by botocore, approximate)\n"
              f"  coverage of observed calls: {'complete' if r['coverage']['complete'] else 'MISSING ' + str(r['coverage']['missing'])}\n"
              f"  escalation: {r['category_before']} -> {r['category_after']}\n"
              f"  left out as sensitive: {', '.join(n['sensitive_left_out']) or 'none'}; unscoped: {', '.join(n['unscoped_actions']) or 'none'}\n"
              f"  policy ({n['policy_chars']} chars, {'fits' if n['fits_managed_policy'] else 'TOO BIG for'} a managed policy) -> {path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--endpoint", default=os.environ.get("AEGIS_ENDPOINT"))
    c.add_argument("--account")
    c.add_argument("--out")
    t = sub.add_parser("trail")
    t.add_argument("--endpoint", default=os.environ.get("AEGIS_ENDPOINT"))
    t.add_argument("--out")
    s = sub.add_parser("scan")
    s.add_argument("snapshots", nargs="+")
    s.add_argument("--scp", nargs="*", default=[])
    s.add_argument("--policy")
    s.add_argument("--write", action="store_true")
    s.add_argument("--fail-on-path", action="store_true", help="exit 1 if any principal escalates or is an unexpected admin (CI gate)")
    lp = sub.add_parser("leastpriv")
    lp.add_argument("--snapshot", required=True)
    lp.add_argument("--trail", required=True, help="a CloudTrail JSON/JSONL file or a directory of them")
    lp.add_argument("--principal")
    lp.add_argument("--keep-sensitive", action="store_true")
    lp.add_argument("--scp", nargs="*", default=[])
    lp.add_argument("--policy")
    lp.add_argument("--out-dir")
    cy = sub.add_parser("cypher")
    cy.add_argument("snapshot")
    a = ap.parse_args()
    if a.cmd == "cypher":
        sys.stdout.write(cypher.export(snapshot.load(a.snapshot)))
        return 0
    return {"collect": cmd_collect, "trail": cmd_trail, "scan": cmd_scan, "leastpriv": cmd_leastpriv}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
