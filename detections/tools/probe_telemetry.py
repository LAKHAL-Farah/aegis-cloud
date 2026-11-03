#!/usr/bin/env python3
"""Answer the four open telemetry questions from Stage 2 in one run, on the PURPLE twin only.

  1. Does the trail deliver real log files to S3 (not just the prefix)?     -> S3 source usable?
  2. After StopLogging, is StopLogging / StartLogging recorded?             -> S04 telemetry
  3. Are S3 data events (GetObject) delivered?                              -> S02 detectable at all?
  4. What do events look like (identity, user agent, request parameters)?   -> which rules can work
Also measures delivery latency and the clock difference between this host and LocalStack.

Writes build/logsource.json (read by `detect.py watch --source auto`) and docs/evidence/telemetry-probe.md.
Everything it does is reversible and uses the account root of the purple twin."""
from __future__ import annotations

import gzip
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
WAIT_S = int(os.environ.get("PROBE_WAIT_S", "90"))


def client(service, account):
    return boto3.client(service, endpoint_url=ENDPOINT, region_name="us-east-1", aws_access_key_id=account,
                        aws_secret_access_key="test", config=Config(retries={"max_attempts": 1}))


def trail_records(s3, bucket, account):
    out = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"AWSLogs/{account}/CloudTrail/"):
        for obj in page.get("Contents", []):
            if not obj["Key"].endswith((".json", ".json.gz")):
                continue
            body = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            body = gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body
            try:
                out += [(obj["Key"], r) for r in json.loads(body).get("Records", [])]
            except ValueError:
                pass
    return out


def wait_for(fn, seconds):
    start = time.time()
    while time.time() - start < seconds:
        hit = fn()
        if hit:
            return hit, time.time() - start
        time.sleep(3)
    return None, time.time() - start


def main() -> int:
    host = (ENDPOINT.split("//")[-1].split(":")[0]).lower()
    if host not in {"localhost", "127.0.0.1", "localstack"}:
        sys.exit("refusing: not a LocalStack endpoint")
    path = ROOT / "build" / "range" / "targets.json"
    if not path.exists():
        sys.exit("run `make range-up` first")
    t = json.loads(path.read_text())["purple"]
    acct, res = t["account_id"], t["resources"]
    ct, s3, iam = client("cloudtrail", acct), client("s3", acct), client("iam", acct)
    trail, bucket, data_bucket = res["trail_name"], res["trail_bucket"], res["data_bucket"]
    tag = uuid.uuid4().hex[:6]
    probe_user = f"probe-{tag}"
    f: dict = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "account": acct, "notes": []}

    # clock difference between this host and LocalStack (via the S3 Date header)
    try:
        resp = s3.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"].get("date")
        remote = datetime.strptime(resp, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
        f["clock_skew_s"] = round((remote - datetime.now(timezone.utc)).total_seconds(), 1)
    except Exception as exc:  # noqa: BLE001
        f["clock_skew_s"] = None
        f["notes"].append(f"could not measure clock skew: {exc}")

    status = ct.get_trail_status(Name=trail)
    f["trail_is_logging"] = bool(status.get("IsLogging"))
    if not f["trail_is_logging"]:
        ct.start_logging(Name=trail)

    # ---- generate known activity
    started = datetime.now(timezone.utc)
    iam.create_user(UserName=probe_user)
    s3.list_objects_v2(Bucket=data_bucket)
    first_key = next(iter(s3.list_objects_v2(Bucket=data_bucket).get("Contents", [])), {}).get("Key")
    if first_key:
        s3.get_object(Bucket=data_bucket, Key=first_key)["Body"].read()
    ct.stop_logging(Name=trail)
    time.sleep(2)
    ct.start_logging(Name=trail)
    iam.delete_user(UserName=probe_user)

    # ---- 2. lookup_events view (management events)
    seen_lookup: dict[str, int] = {}
    def lookup():
        for name in ("CreateUser", "StopLogging", "StartLogging", "DeleteUser"):
            if name in seen_lookup:
                continue
            r = ct.lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                                 StartTime=started, MaxResults=10)
            if r.get("Events"):
                seen_lookup[name] = len(r["Events"])
        return len(seen_lookup) == 4
    wait_for(lookup, 20)
    f["lookup_events"] = {k: (k in seen_lookup) for k in ("CreateUser", "StopLogging", "StartLogging", "DeleteUser")}

    # ---- 1 + 3 + 4. S3 delivery
    def delivered():
        recs = [r for _, r in trail_records(s3, bucket, acct)]
        return recs if any(r.get("eventName") == "CreateUser" and probe_user in json.dumps(r) for r in recs) else None
    recs, latency = wait_for(delivered, WAIT_S)
    all_recs = [r for _, r in trail_records(s3, bucket, acct)]
    f["s3_files"] = len({k for k, _ in trail_records(s3, bucket, acct)})
    f["s3_delivers_log_files"] = bool(recs)
    f["s3_latency_s"] = round(latency, 1) if recs else None
    names = {r.get("eventName") for r in all_recs}
    f["s3_has"] = {n: n in names for n in ("CreateUser", "StopLogging", "StartLogging", "GetObject")}
    # only a read of the DATA bucket counts: our own reads of the trail's log files are recorded too and prove nothing
    f["s3_data_events"] = any(r.get("eventName") == "GetObject" and
                              (r.get("requestParameters") or {}).get("bucketName") == data_bucket
                              for r in all_recs)
    sample = next((r for r in all_recs if r.get("eventName") == "CreateUser"), None) or (all_recs[0] if all_recs else {})
    ident = sample.get("userIdentity") or {}
    f["shape"] = {"has_userIdentity_arn": bool(ident.get("arn")), "has_userName": bool(ident.get("userName")),
                  "has_userAgent": bool(sample.get("userAgent")), "has_eventID": bool(sample.get("eventID")),
                  "has_requestParameters": bool(sample.get("requestParameters")),
                  "has_readOnly": "readOnly" in sample, "has_eventCategory": "eventCategory" in sample}
    f["sample_event"] = sample

    # ---- decision
    f["recommended"] = "s3" if f["s3_delivers_log_files"] else "lookup"
    if not f["s3_delivers_log_files"]:
        f["notes"].append("no CloudTrail log files arrived in the trail bucket: using lookup_events (management events only). "
                          "S3 data events (S02, S12 deletes) will not be detectable. Record this in docs/localstack-limitations.md.")
    if f["s3_delivers_log_files"] and not f["s3_data_events"]:
        f["notes"].append("log files arrive but contain no data events: S02 is expected to be a documented miss.")
    if not f["shape"]["has_userIdentity_arn"]:
        f["notes"].append("events carry no userIdentity.arn: identity-based rules fall back to user name / access key / 'unknown'.")
    agent = str(sample.get("userAgent") or "")
    f["user_agent_seen"] = agent
    f["shape"]["user_agent_is_ours"] = "botocore" in agent.lower() or "boto3" in agent.lower()
    if agent and not f["shape"]["user_agent_is_ours"]:
        f["notes"].append(f"the recorded user agent is {agent!r}, not the client's own (the probe used boto3): LocalStack "
                          "overwrites it, so S08 cannot be detected from CloudTrail here. Documented miss.")
    if not f["shape"]["has_userAgent"]:
        f["notes"].append("events carry no userAgent: the interactive-client rule cannot work, S08 is expected to be a documented miss.")
    if not f["lookup_events"]["StopLogging"] and not f["s3_has"]["StopLogging"]:
        f["notes"].append("StopLogging was recorded nowhere: the state-based trail rule is the only way to see S04.")

    (ROOT / "build").mkdir(exist_ok=True)
    (ROOT / "build" / "logsource.json").write_text(json.dumps(f, indent=2, default=str))
    out = ROOT / "docs" / "evidence" / "telemetry-probe.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    yn = lambda b: "yes" if b else "NO"  # noqa: E731
    lines = [f"# Telemetry probe ({f['generated']})", "", f"Purple account {acct}. Recommended source: **{f['recommended']}**.", "",
             "| Question | Answer |", "| --- | --- |",
             f"| Trail delivers real log files to S3 | {yn(f['s3_delivers_log_files'])} ({f['s3_files']} files, latency {f['s3_latency_s']} s) |",
             f"| `lookup_events` returns CreateUser / StopLogging / StartLogging / DeleteUser | "
             + " / ".join(yn(v) for v in f["lookup_events"].values()) + " |",
             f"| S3 delivery contains StopLogging / StartLogging | {yn(f['s3_has']['StopLogging'])} / {yn(f['s3_has']['StartLogging'])} |",
             f"| S3 data events (GetObject) delivered | {yn(f['s3_data_events'])} |",
             f"| Event has userIdentity.arn / userName / userAgent | {yn(f['shape']['has_userIdentity_arn'])} / {yn(f['shape']['has_userName'])} / {yn(f['shape']['has_userAgent'])} |",
             f"| Event has eventID / requestParameters / readOnly / eventCategory | {yn(f['shape']['has_eventID'])} / {yn(f['shape']['has_requestParameters'])} / {yn(f['shape']['has_readOnly'])} / {yn(f['shape']['has_eventCategory'])} |",
             f"| Clock difference host vs LocalStack | {f['clock_skew_s']} s |", "", "## Consequences", ""]
    lines += [f"* {n}" for n in f["notes"]] or ["* none: everything the rules need is present."]
    lines += ["", "## One real event (CreateUser)", "", "```json", json.dumps(sample, indent=2, default=str)[:3000], "```", ""]
    out.write_text("\n".join(lines))
    print("\n".join(lines[:16]))
    print(f"\nwrote {out} and build/logsource.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())