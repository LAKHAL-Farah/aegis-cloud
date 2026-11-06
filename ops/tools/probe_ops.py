#!/usr/bin/env python3
"""Stage 5 capability probe: which operations features does this LocalStack actually implement?

Run it BEFORE believing any Stage 5 claim and BEFORE turning on enable_backup / enable_patching. Writes
docs/evidence/ops-probe.md. Verdicts: WORKS (behaves), STORED ONLY (the API accepts it, nothing happens),
NOT SUPPORTED (error), and the detail says which call decided it.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
ACCOUNTS = {"management": "111111111111", "security": "333333333333", "workload": "444444444444"}
WORKS, STORED, NOPE = "WORKS", "STORED ONLY", "NOT SUPPORTED"


def make_client(service: str, account: str):
    import boto3
    return boto3.client(service, endpoint_url=ENDPOINT, region_name="us-east-1",
                        aws_access_key_id=ACCOUNTS[account], aws_secret_access_key="test")


def probe_metrics(client, wait_s=0):
    cw = client("cloudwatch", "security")
    cw.put_metric_data(Namespace="Aegis/Probe", MetricData=[{"MetricName": "Up", "Value": 1.0, "Dimensions": [{"Name": "C", "Value": "x"}]}])
    got = cw.get_metric_statistics(Namespace="Aegis/Probe", MetricName="Up", Dimensions=[{"Name": "C", "Value": "x"}],
                                   StartTime=datetime.fromtimestamp(time.time() - 600, tz=timezone.utc),
                                   EndTime=datetime.fromtimestamp(time.time() + 60, tz=timezone.utc), Period=60, Statistics=["Maximum"])
    return (WORKS, "put_metric_data then get_metric_statistics returned the point") if got["Datapoints"] else \
           (STORED, "put_metric_data accepted but get_metric_statistics returned nothing")


def probe_alarm_state(client, wait_s=0):
    cw = client("cloudwatch", "security")
    cw.put_metric_alarm(AlarmName="aegis-probe-missing", Namespace="Aegis/Probe", MetricName="NeverPublished", Statistic="Minimum",
                        Period=60, EvaluationPeriods=1, Threshold=1, ComparisonOperator="LessThanThreshold", TreatMissingData="breaching")
    cw.set_alarm_state(AlarmName="aegis-probe-missing", StateValue="ALARM", StateReason="probe")
    forced = cw.describe_alarms(AlarmNames=["aegis-probe-missing"])["MetricAlarms"][0]["StateValue"]
    if forced != "ALARM":
        return STORED, f"set_alarm_state did not stick (state {forced})"
    if not wait_s:
        return STORED, "alarm definitions and forced state work; automatic evaluation not tested (use --wait 150)"
    cw.set_alarm_state(AlarmName="aegis-probe-missing", StateValue="OK", StateReason="reset")
    time.sleep(wait_s)
    state = cw.describe_alarms(AlarmNames=["aegis-probe-missing"])["MetricAlarms"][0]["StateValue"]
    return (WORKS, f"a breaching-on-missing alarm went OK -> {state} on its own") if state == "ALARM" else \
           (STORED, f"alarm stayed {state} after {wait_s} s: LocalStack does not evaluate it, so pipeline alarms are definitions only")


def probe_metric_filter(client, wait_s=0):
    logs = client("logs", "management")
    group = "/aegis/probe"
    try:
        logs.create_log_group(logGroupName=group)
    except Exception:  # noqa: BLE001 - already exists
        pass
    logs.put_metric_filter(logGroupName=group, filterName="probe", filterPattern='{ $.eventName = "StopLogging" }',
                           metricTransformations=[{"metricName": "ProbeStop", "metricNamespace": "Aegis/Probe", "metricValue": "1"}])
    logs.create_log_stream(logGroupName=group, logStreamName="s") if not logs.describe_log_streams(logGroupName=group)["logStreams"] else None
    logs.put_log_events(logGroupName=group, logStreamName="s",
                        logEvents=[{"timestamp": int(time.time() * 1000), "message": '{"eventName":"StopLogging"}'}])
    time.sleep(max(wait_s, 3))
    cw = client("cloudwatch", "management")
    got = cw.get_metric_statistics(Namespace="Aegis/Probe", MetricName="ProbeStop",
                                   StartTime=datetime.fromtimestamp(time.time() - 600, tz=timezone.utc),
                                   EndTime=datetime.fromtimestamp(time.time() + 60, tz=timezone.utc), Period=60, Statistics=["Sum"])
    return (WORKS, "a matching log event produced the metric") if got["Datapoints"] else \
           (STORED, "filter stored, but a matching event produced no metric: CIS section 4 alarms cannot fire here")


def probe_trail_delivery(client, wait_s=0):
    ct = client("cloudtrail", "management")
    trails = ct.describe_trails()["trailList"]
    arn = next((t.get("CloudWatchLogsLogGroupArn") for t in trails if t.get("CloudWatchLogsLogGroupArn")), None)
    if not arn:
        return NOPE, "no trail with a CloudWatchLogsLogGroupArn (apply the management root with enable_cloudwatch_logs, or LocalStack drops it)"
    group = arn.split(":log-group:")[1].removesuffix(":*")
    events = client("logs", "management").filter_log_events(logGroupName=group, limit=1)["events"]
    return (WORKS, f"events from CloudTrail arrived in {group}") if events else \
           (STORED, f"the trail points at {group} but no CloudTrail event was delivered there")


def probe_ssm(client, wait_s=0):
    ssm = client("ssm", "workload")
    base = ssm.create_patch_baseline(Name="aegis-probe", OperatingSystem="AMAZON_LINUX_2023")["BaselineId"]
    try:
        ssm.delete_patch_baseline(BaselineId=base)
        window = ssm.create_maintenance_window(Name="aegis-probe", Schedule="cron(0 4 ? * SUN *)", Duration=3, Cutoff=1,
                                               AllowUnassociatedTargets=False)["WindowId"]
        ssm.delete_maintenance_window(WindowId=window)
    except Exception as exc:  # noqa: BLE001
        return STORED, f"patch baseline works, maintenance window did not: {type(exc).__name__}"
    try:
        cmd = ssm.send_command(DocumentName="AWS-RunShellScript", InstanceIds=["i-0123456789abcdef0"],
                               Parameters={"commands": ["echo hi"]})["Command"]["CommandId"]
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
        return STORED, ("patch baseline and maintenance window definitions work; Run Command is rejected "
                        f"({code}) for an instance that does not exist, so it can only be tried on a real LocalStack EC2 instance")
    inv = ssm.list_command_invocations(CommandId=cmd, Details=True)["CommandInvocations"]
    return STORED, ("patch baseline and maintenance window definitions work; Run Command is accepted "
                    f"({len(inv)} invocation record(s)) but no instance executes anything")


def probe_backup(client, wait_s=0):
    b = client("backup", "workload")
    b.create_backup_vault(BackupVaultName="aegis-probe")
    plan = b.create_backup_plan(BackupPlan={"BackupPlanName": "aegis-probe", "Rules": [{
        "RuleName": "d", "TargetBackupVaultName": "aegis-probe", "ScheduleExpression": "cron(0 3 * * ? *)"}]})["BackupPlanId"]
    b.delete_backup_plan(BackupPlanId=plan)
    try:
        job = b.start_backup_job(BackupVaultName="aegis-probe", ResourceArn="arn:aws:s3:::aegis-data-444444444444",
                                 IamRoleArn="arn:aws:iam::444444444444:role/aegis-backup")["BackupJobId"]
    except Exception as exc:  # noqa: BLE001
        err = getattr(exc, "response", {}).get("Error", {})
        return STORED, f"vault and plan accepted; start_backup_job failed: {err.get('Code', type(exc).__name__)}: {str(err.get('Message', exc))[:120]}"
    time.sleep(max(wait_s, 3))
    state = b.describe_backup_job(BackupJobId=job)["State"]
    return (WORKS, f"a backup job reached {state}") if state == "COMPLETED" else \
           (STORED, f"vault, plan and job accepted; the job is {state}, not COMPLETED: no restore claim from AWS Backup")


def probe_s3_versions(client, wait_s=0):
    s3 = client("s3", "workload")
    bucket = f"aegis-probe-{int(time.time())}"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=bucket, Key="k", Body=b"1")
    s3.put_object(Bucket=bucket, Key="k", Body=b"2")
    versions = s3.list_object_versions(Bucket=bucket)["Versions"]
    ok = len(versions) == 2
    for v in versions:
        s3.delete_object(Bucket=bucket, Key="k", VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)
    return (WORKS, "two writes kept two versions: the restore drill can rely on this") if ok else \
           (NOPE, f"versioning kept {len(versions)} version(s)")


PROBES = [("CloudWatch custom metrics", probe_metrics), ("CloudWatch alarm states", probe_alarm_state),
          ("Logs metric filter fires", probe_metric_filter), ("CloudTrail -> CloudWatch Logs delivery", probe_trail_delivery),
          ("SSM Patch Manager and Run Command", probe_ssm), ("AWS Backup jobs", probe_backup),
          ("S3 versioning (restore drill)", probe_s3_versions)]


def run_all(client=make_client, wait_s=0, probes=PROBES):
    rows = []
    for name, fn in probes:
        try:
            verdict, detail = fn(client, wait_s)
        except Exception as exc:  # noqa: BLE001 - a probe never aborts the run
            code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
            verdict, detail = NOPE, f"{code}: {str(exc)[:140]}"
        rows.append((name, verdict, detail))
    return rows


def render(rows) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"# Stage 5 capability probe ({stamp})", "", f"Endpoint {ENDPOINT}. Record `localstack --version` next to this file.", "",
           "| Capability | Verdict | Evidence |", "| --- | --- | --- |"]
    out += [f"| {n} | **{v}** | {d} |" for n, v, d in rows]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wait", type=int, default=0, help="seconds to wait for alarm evaluation (150 is a fair test)")
    ap.add_argument("--out", default=str(ROOT / "docs" / "evidence" / "ops-probe.md"))
    args = ap.parse_args(argv)
    from urllib.parse import urlparse
    if (urlparse(ENDPOINT).hostname or "") not in {"localhost", "127.0.0.1", "localstack"}:
        sys.exit("refusing: endpoint is not LocalStack")
    rows = run_all(wait_s=args.wait)
    md = render(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(md)
    print(md)
    return 0


if __name__ == "__main__":
    sys.exit(main())
