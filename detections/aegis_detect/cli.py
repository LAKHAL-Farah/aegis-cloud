"""Command line: watch | once | rules | eval.   See `make detect-help`."""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

import boto3
from botocore.config import Config

from . import sources
from .engine import Engine
from .model import Event
from .policy import Policy
from .rules import all_rules
from .sinks import EventBridgeSink, FileSink, OpenSearchEvents, OpenSearchSink, SafeSink

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")


def _guard() -> None:
    from urllib.parse import urlparse
    host = (urlparse(ENDPOINT).hostname or "").lower()
    if host not in {"localhost", "127.0.0.1", "localstack", "localstack.localhost"}:
        sys.exit(f"refusing to run: endpoint '{ENDPOINT}' is not LocalStack")


def _client(service: str, account_id: str):
    # On LocalStack the access key IS the account id. The detector reads with the account root here;
    # on real AWS this would be a read-only role in the security account (documented limitation).
    return boto3.client(service, endpoint_url=ENDPOINT, region_name="us-east-1",
                        aws_access_key_id=account_id, aws_secret_access_key="test",
                        config=Config(retries={"max_attempts": 2, "mode": "standard"}))


def _targets() -> dict:
    path = ROOT / "build" / "range" / "targets.json"
    if not path.exists():
        sys.exit("no build/range/targets.json: run `make range-up` first")
    return json.loads(path.read_text())


def _choose_source(arg: str) -> str:
    if arg != "auto":
        return arg
    rec = ROOT / "build" / "logsource.json"
    if rec.exists():
        return json.loads(rec.read_text()).get("recommended", "s3")
    return "s3"


def build_sources(watch: list[str], mode: str, targets: dict, from_now: bool) -> list:
    out = []
    for name in watch:
        t = targets[name]
        acct, res = t["account_id"], t["resources"]
        if mode in ("s3", "both"):
            out.append(sources.S3TrailSource(_client("s3", acct), res["trail_bucket"], acct))
        if mode in ("lookup", "both"):
            out.append(sources.LookupSource(_client("cloudtrail", acct), acct))
        out.append(sources.TrailStateSource(_client("cloudtrail", acct), acct, res["trail_name"]))
    if from_now:
        for s in out:
            s.prime()
    return out


def _mirror(events, directory: Path | None) -> None:
    """Write raw records as JSON lines (one file per account) for Wazuh / OpenSearch to ingest."""
    if not directory or not events:
        return
    directory.mkdir(parents=True, exist_ok=True)
    by_acct: dict[str, list[str]] = {}
    for e in events:
        if e.category == "Observation":
            continue
        rec = dict(e.raw)
        rec["aegis_account_id"] = e.account_id
        by_acct.setdefault(e.account_id, []).append(json.dumps(rec, default=str))
    for acct, lines in by_acct.items():
        with open(directory / f"{acct}.jsonl", "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")


def _sinks(args, targets) -> list:
    sinks = [FileSink(Path(args.alert_dir), Path(args.findings_dir))]
    if args.opensearch:
        sinks.append(SafeSink(OpenSearchSink(args.opensearch), "opensearch"))
    if args.eventbridge:
        acct = targets["purple"]["account_id"]
        sinks.append(SafeSink(EventBridgeSink(_client("events", acct), args.eventbridge), "eventbridge"))
    return sinks


def cmd_watch(args) -> int:
    _guard()
    targets = _targets()
    mode = _choose_source(args.source)
    srcs = build_sources(args.accounts.split(","), mode, targets, from_now=not args.replay)
    engine, sinks = Engine(Policy.load(args.policy)), _sinks(args, targets)
    mirror = Path(args.mirror) if args.mirror else None
    event_index = OpenSearchEvents(args.opensearch) if args.opensearch else None
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
    signal.signal(signal.SIGINT, lambda *_: stop.update(flag=True))
    print(f"detector up: source={mode}, accounts={args.accounts}, interval={args.interval}s, "
          f"{'replaying history' if args.replay else 'from now'}, {len(engine.rules)} rules", flush=True)
    while not stop["flag"]:
        batch: list[Event] = []
        for s in srcs:
            try:
                batch += list(s.poll())
            except Exception as exc:  # noqa: BLE001 - a poll failure must not kill the detector
                print(f"  [warn] {s.name} poll failed: {exc}", flush=True)
        _mirror(batch, mirror)
        if event_index:
            try:
                event_index.index(batch)
            except Exception as exc:  # noqa: BLE001 - the SIEM being down never stops detection
                print(f"  [warn] opensearch events: {exc}", flush=True)
        for det in engine.process(batch):
            for sink in sinks:
                sink.emit(det)
            print(f"  ALERT {det.severity.upper():8} {det.technique:10} {det.rule_id}  {det.summary}", flush=True)
        if args.once:
            break
        time.sleep(args.interval)
    return 0


def cmd_rules(args) -> int:
    print("| Rule | ATT&CK | Tactic | Severity | Title |\n| --- | --- | --- | --- | --- |")
    for r in all_rules():
        print(f"| {r.id} | {r.technique} | {r.tactic} | {r.severity} | {r.title} |")
    return 0


def cmd_eval(args) -> int:
    """Run the rules over saved CloudTrail JSON files ({'Records': [...]}), no LocalStack needed."""
    engine, n = Engine(Policy.load(args.policy)), 0
    events = []
    for f in args.files:
        for rec in json.loads(Path(f).read_text()).get("Records", []):
            events.append(Event.from_cloudtrail(rec, args.account))
    for det in engine.process(events):
        n += 1
        print(f"{det.event_time:%H:%M:%S}  {det.severity:8} {det.technique:10} {det.rule_id}  {det.summary}")
    print(f"{n} detection(s) from {len(events)} event(s)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aegis_detect")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("watch", help="poll the trails and raise alerts live")
    w.add_argument("--source", choices=["auto", "s3", "lookup", "both"], default="auto")
    w.add_argument("--accounts", default="purple", help="comma list: purple,hardened")
    w.add_argument("--interval", type=float, default=3.0)
    w.add_argument("--replay", action="store_true", help="process history too (rule development)")
    w.add_argument("--once", action="store_true", help="one poll, then exit")
    w.add_argument("--alert-dir", default=str(ROOT / "build" / "alerts"))
    w.add_argument("--findings-dir", default=str(ROOT / "build" / "findings"))
    w.add_argument("--mirror", default=None, help="directory for raw JSONL (feeds Wazuh)")
    w.add_argument("--opensearch", default=None, help="e.g. http://localhost:9200")
    w.add_argument("--eventbridge", default=None, help="bus name, e.g. aegis-findings")
    w.add_argument("--policy", default=None)
    w.set_defaults(fn=cmd_watch)

    r = sub.add_parser("rules", help="list rules as a markdown table")
    r.set_defaults(fn=cmd_rules)

    e = sub.add_parser("eval", help="run rules over saved CloudTrail JSON files")
    e.add_argument("files", nargs="+")
    e.add_argument("--account", default="000000000000", help="account id to attribute the events to")
    e.add_argument("--policy", default=None)
    e.set_defaults(fn=cmd_eval)

    args = ap.parse_args(argv)
    return args.fn(args)