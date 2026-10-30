#!/usr/bin/env python3
"""AegisCloud compliance score (ADR-0003).

Merges three evidence sources per CIS control:
  1. Checkov on the Terraform code      (preventive)
  2. OPA/Conftest rules on the plan     (preventive, run `make plan-json` first)
  3. boto3 checks against LocalStack    (detective: what is really deployed)

A control is PASS / FAIL / NOT_EVALUATED. NOT_EVALUATED is never counted as a pass.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parent.parent
ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"
ACCOUNTS = {
    "management": "111111111111",
    "log_archive": "222222222222",
    "security": "333333333333",
    "workload": "444444444444",
}
PASS, FAIL, NE = "PASS", "FAIL", "NOT_EVALUATED"


def client(service: str, account: str):
    """boto3 client acting as one account (on LocalStack the access key IS the account ID)."""
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        region_name=REGION,
        aws_access_key_id=ACCOUNTS[account],
        aws_secret_access_key="test",
    )


# ---------------------------------------------------------------- live checks (detective)
def root_mfa():
    return NE, "root MFA is not emulated by LocalStack"


def password_policy_length():
    p = client("iam", "workload").get_account_password_policy()["PasswordPolicy"]
    n = p.get("MinimumPasswordLength", 0)
    return (PASS if n >= 14 else FAIL), f"MinimumPasswordLength={n}"


def password_policy_reuse():
    p = client("iam", "workload").get_account_password_policy()["PasswordPolicy"]
    n = p.get("PasswordReusePrevention", 0)
    return (PASS if n >= 24 else FAIL), f"PasswordReusePrevention={n}"


def _trails():
    ct = client("cloudtrail", "management")
    return ct, ct.describe_trails()["trailList"]


def trail_multi_region():
    ct, trails = _trails()
    multi = [t for t in trails if t.get("IsMultiRegionTrail")]
    if not multi:
        return FAIL, "no multi-region trail"
    logging_on = ct.get_trail_status(Name=multi[0]["TrailARN"]).get("IsLogging")
    return (PASS if logging_on else FAIL), f"{multi[0]['Name']} IsLogging={logging_on}"


def trail_validation():
    _, trails = _trails()
    bad = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
    if not trails:
        return FAIL, "no trails"
    return (PASS if not bad else FAIL), f"without validation: {bad or 'none'}"


def trail_kms():
    _, trails = _trails()
    bad = [t["Name"] for t in trails if not t.get("KmsKeyId")]
    if not trails:
        return FAIL, "no trails"
    return (PASS if not bad else FAIL), f"without KMS: {bad or 'none'}"


def trail_bucket_logging():
    _, trails = _trails()
    if not trails:
        return FAIL, "no trails"
    bucket = trails[0]["S3BucketName"]
    resp = client("s3", "log_archive").get_bucket_logging(Bucket=bucket)
    return (PASS if "LoggingEnabled" in resp else FAIL), f"{bucket} logging={'LoggingEnabled' in resp}"


def s3_public_block():
    bad, seen = [], 0
    for acct in ACCOUNTS:
        s3 = client("s3", acct)
        for b in s3.list_buckets()["Buckets"]:
            seen += 1
            try:
                cfg = s3.get_public_access_block(Bucket=b["Name"])["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    bad.append(f"{acct}:{b['Name']}")
            except ClientError:
                bad.append(f"{acct}:{b['Name']} (none)")
    if seen == 0:
        return NE, "no buckets found"
    return (PASS if not bad else FAIL), f"{seen} buckets, unprotected: {bad or 'none'}"


def sg_admin_ports():
    bad = []
    for sg in client("ec2", "workload").describe_security_groups()["SecurityGroups"]:
        for perm in sg.get("IpPermissions", []):
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            all_proto = perm.get("IpProtocol") == "-1"
            if world and (all_proto or any(lo <= p <= hi for p in (22, 3389))):
                bad.append(sg["GroupId"])
    return (PASS if not bad else FAIL), f"world-open admin SGs: {sorted(set(bad)) or 'none'}"


def default_sg_closed():
    ec2 = client("ec2", "workload")
    ours = {v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"] if not v.get("IsDefault")}
    if not ours:
        return NE, "no non-default VPC"
    bad = []
    for sg in ec2.describe_security_groups()["SecurityGroups"]:
        if sg["GroupName"] == "default" and sg.get("VpcId") in ours \
                and (sg.get("IpPermissions") or sg.get("IpPermissionsEgress")):
            bad.append(sg["GroupId"])
    return (PASS if not bad else FAIL), f"default SGs with rules in our VPCs: {bad or 'none'}"

def vpc_flow_logs():
    ec2 = client("ec2", "workload")
    vpcs = [v["VpcId"] for v in ec2.describe_vpcs()["Vpcs"] if not v.get("IsDefault")]
    if not vpcs:
        return NE, "no non-default VPC"
    missing = []
    for vpc in vpcs:
        flows = ec2.describe_flow_logs(Filter=[{"Name": "resource-id", "Values": [vpc]}])["FlowLogs"]
        if not flows:
            missing.append(vpc)
    return (PASS if not missing else FAIL), f"VPCs without flow logs: {missing or 'none'}"


def kms_rotation():
    bad, seen = [], 0
    for acct in ("log_archive", "workload"):
        kms = client("kms", acct)
        for k in kms.list_keys()["Keys"]:
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                continue
            seen += 1
            if not kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]:
                bad.append(f"{acct}:{k['KeyId']}")
    if seen == 0:
        return NE, "no customer keys found"
    return (PASS if not bad else FAIL), f"{seen} keys, without rotation: {bad or 'none'}"


LIVE = {
    f.__name__: f
    for f in (
        root_mfa, password_policy_length, password_policy_reuse, trail_multi_region, trail_validation,
        trail_kms, trail_bucket_logging, s3_public_block, sg_admin_ports, default_sg_closed,
        vpc_flow_logs, kms_rotation,
    )
}


def run_live(names: set[str]) -> dict[str, tuple[str, str]]:
    results = {}
    for name in sorted(names):
        try:
            results[name] = LIVE[name]()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NoSuchEntity", "NoSuchPublicAccessBlockConfiguration"):
                results[name] = (FAIL, f"not configured ({code})")
            else:
                results[name] = (NE, f"API error: {code}")
        except Exception as exc:  # LocalStack unreachable, feature missing, etc.
            results[name] = (NE, f"{type(exc).__name__}: {exc}")
    return results


# ---------------------------------------------------------------- preventive sources
def run_checkov():
    if not shutil.which("checkov"):
        print("note: checkov not on PATH (activate .venv); skipping Checkov evidence", file=sys.stderr)
        return None
    proc = subprocess.run(
        ["checkov", "-d", str(ROOT / "terraform/live"),
         "--config-file", str(ROOT / "policies/checkov/.checkov.yaml"), "-o", "json"],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("note: could not parse Checkov output; skipping", file=sys.stderr)
        return None
    reports = data if isinstance(data, list) else [data]
    failed, ran = set(), set()
    for rep in reports:
        res = rep.get("results", {})
        failed |= {c["check_id"] for c in res.get("failed_checks", [])}
        ran |= {c["check_id"] for c in res.get("passed_checks", [])}
    return {"failed": failed, "ran": ran | failed}


def run_conftest():
    plans = sorted((ROOT / "build/plans").glob("*.json"))
    if not (shutil.which("conftest") and plans):
        print("note: conftest or build/plans missing (run `make plan-json`); skipping OPA evidence", file=sys.stderr)
        return None
    proc = subprocess.run(
        ["conftest", "test", "--policy", str(ROOT / "policies/opa"), "-o", "json", *map(str, plans)],
        capture_output=True, text=True,
    )
    failed = set()
    for res in json.loads(proc.stdout or "[]"):
        for f in res.get("failures") or []:
            m = re.match(r"\[(AEG-[A-Z]+-\d+)\]", f.get("msg", ""))
            if m:
                failed.add(m.group(1))
    return {"failed": failed}


# ---------------------------------------------------------------- scoring
def evaluate(control, checkov, conftest, live):
    evidence = []  # (status, label)
    for cid in control.get("checkov", []):
        if checkov and cid in checkov["failed"]:
            evidence.append((FAIL, f"checkov {cid}"))
        elif checkov and cid in checkov["ran"]:
            evidence.append((PASS, f"checkov {cid}"))
    if conftest is not None:
        for rid in control.get("rego", []):
            evidence.append((FAIL if rid in conftest["failed"] else PASS, f"rego {rid}"))
    if control.get("live"):
        status, detail = live[control["live"]]
        evidence.append((status, f"live {control['live']}: {detail}"))
    statuses = {s for s, _ in evidence}
    if FAIL in statuses:
        overall = FAIL
    elif PASS in statuses:
        overall = PASS
    else:
        overall = NE
    return overall, evidence


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "build/compliance"), help="output directory")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any control FAILS")
    args = ap.parse_args()

    controls = json.loads((ROOT / "policies/cis_controls.json").read_text())
    checkov, conftest = run_checkov(), run_conftest()
    live = run_live({c["live"] for c in controls if c.get("live")})

    rows = []
    for c in controls:
        overall, evidence = evaluate(c, checkov, conftest, live)
        rows.append({"id": c["id"], "title": c["title"], "status": overall,
                     "note": c.get("note"), "evidence": [e for _, e in evidence]})

    passing = sum(r["status"] == PASS for r in rows)
    failing = sum(r["status"] == FAIL for r in rows)
    not_eval = sum(r["status"] == NE for r in rows)
    evaluable = passing + failing
    summary = (f"AegisCloud CIS score: {passing} of {evaluable} evaluable controls passing "
               f"({not_eval} not evaluated)")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    (out / "score.json").write_text(json.dumps(
        {"generated": stamp, "passing": passing, "failing": failing, "not_evaluated": not_eval, "controls": rows},
        indent=2))
    md = [f"# {summary}", "", f"_Generated {stamp} against LocalStack at {ENDPOINT}_", "",
          "| CIS | Control | Status | Evidence |", "| --- | --- | --- | --- |"]
    for r in rows:
        ev = "<br>".join(r["evidence"]) or (r["note"] or "no check available")
        md.append(f"| {r['id']} | {r['title']} | {r['status']} | {ev} |")
    (out / "score.md").write_text("\n".join(md) + "\n")

    print(summary)
    for r in rows:
        print(f"  {r['status']:<14} {r['id']:<6} {r['title']}")
    print(f"\nwrote {out}/score.json and score.md")
    if args.strict and failing:
        sys.exit(1)


if __name__ == "__main__":
    main()