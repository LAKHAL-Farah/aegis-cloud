#!/usr/bin/env python3
"""Which CloudWatch Logs filter patterns does this LocalStack actually match?

The Stage 5 probe showed a simple pattern firing, but the CIS section 4 patterns are compound and did not. This sends the
same three CloudTrail-shaped events through a ladder of patterns, from simple to the real CIS ones (read from the Terraform
module, never retyped), and prints which produced a metric. It says WHICH shape fails; it never edits the CIS patterns.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
GROUP = "/aegis/probe-filters"
EVENTS = [  # shaped like CloudTrail records, one per CIS family we try
    {"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com"},
    {"eventName": "DisableKey", "eventSource": "kms.amazonaws.com"},
    {"eventName": "AuthorizeSecurityGroupIngress", "eventSource": "ec2.amazonaws.com"},
]


def cis_pattern(key_prefix: str) -> str:
    text = (ROOT / "terraform/modules/monitoring/main.tf").read_text()
    m = re.search(rf'"{key_prefix}[a-z_]*" = {{\s*title\s*=\s*"[^"]*"\s*pattern\s*=\s*"((?:[^"\\]|\\.)*)"', text)
    if not m:
        raise SystemExit(f"CIS pattern {key_prefix} not found in the monitoring module")
    return m.group(1).replace('\\"', '"')


def ladder() -> list[tuple[str, str]]:
    return [
        ("simple, quoted value", '{ $.eventName = "StopLogging" }'),
        ("simple, unquoted value", "{ $.eventName = StopLogging }"),
        ("two terms with ||, parenthesised", "{ ($.eventName = StopLogging) || ($.eventName = StartLogging) }"),
        ("&& with a nested ||", "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"),
        ("REAL CIS 4.5 (CloudTrail changes)", cis_pattern("4_05")),
        ("REAL CIS 4.7 (CMK disable/delete)", cis_pattern("4_07")),
        ("REAL CIS 4.10 (security groups)", cis_pattern("4_10")),
    ]


def run(logs, cw, wait_s: float = 8.0, rows=None):
    rows = rows or ladder()
    try:
        logs.create_log_group(logGroupName=GROUP)
    except Exception:  # noqa: BLE001 - exists
        pass
    stamp = str(int(time.time()))
    for i, (_, pattern) in enumerate(rows):
        logs.put_metric_filter(logGroupName=GROUP, filterName=f"probe-{stamp}-{i}", filterPattern=pattern,
                               metricTransformations=[{"metricName": f"Pat{stamp}_{i}", "metricNamespace": "Aegis/ProbeFilters",
                                                       "metricValue": "1"}])
    logs.create_log_stream(logGroupName=GROUP, logStreamName=f"s{stamp}")
    now = int(time.time() * 1000)
    logs.put_log_events(logGroupName=GROUP, logStreamName=f"s{stamp}",
                        logEvents=[{"timestamp": now + k, "message": json.dumps(e)} for k, e in enumerate(EVENTS)])
    time.sleep(wait_s)
    out = []
    for i, (name, pattern) in enumerate(rows):
        pts = cw.get_metric_statistics(Namespace="Aegis/ProbeFilters", MetricName=f"Pat{stamp}_{i}",
                                       StartTime=datetime.fromtimestamp(time.time() - 900, tz=timezone.utc),
                                       EndTime=datetime.fromtimestamp(time.time() + 120, tz=timezone.utc),
                                       Period=60, Statistics=["Sum"])["Datapoints"]
        out.append((name, bool(pts), pattern))
    for i, _ in enumerate(rows):                      # tidy up our filters
        try:
            logs.delete_metric_filter(logGroupName=GROUP, filterName=f"probe-{stamp}-{i}")
        except Exception:  # noqa: BLE001
            pass
    return out


def render(results) -> str:
    lines = ["| Pattern shape | Matched? |", "| --- | --- |"]
    lines += [f"| {n} | {'**yes**' if ok else 'no'} |" for n, ok, _ in results]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wait", type=float, default=8.0)
    ap.add_argument("--out", default=str(ROOT / "docs" / "evidence" / "filter-probe.md"))
    args = ap.parse_args(argv)
    from urllib.parse import urlparse
    if (urlparse(ENDPOINT).hostname or "") not in {"localhost", "127.0.0.1", "localstack"}:
        sys.exit("refusing: endpoint is not LocalStack")
    import boto3
    kw = dict(endpoint_url=ENDPOINT, region_name="us-east-1", aws_access_key_id="111111111111", aws_secret_access_key="test")
    results = run(boto3.client("logs", **kw), boto3.client("cloudwatch", **kw), args.wait)
    md = (f"# Log filter pattern probe ({datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})\n\n"
          "Three CloudTrail-shaped events were sent through each pattern; `yes` means a metric datapoint appeared. "
          "Record `localstack --version` next to this file.\n\n" + render(results))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
