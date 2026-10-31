#!/usr/bin/env python3
"""Static misconfiguration check of both twins (what a CSPM would flag). Not attack detection."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from botocore.exceptions import ClientError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from attacks.context import Context, Target  # noqa: E402

ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT", "http://localhost:4566")


def checks(ctx: Context) -> list[tuple[str, bool, str]]:
    r, out = ctx.res, []
    s3 = ctx.admin("s3")
    try:
        cfg = s3.get_public_access_block(Bucket=r["data_bucket"])["PublicAccessBlockConfiguration"]
        out.append(("data bucket blocks public access", all(cfg.values()), str(cfg)))
    except ClientError as exc:
        out.append(("data bucket blocks public access", False, exc.response["Error"]["Code"]))

    iam = ctx.admin("iam")
    boundary = iam.get_user(UserName=r["dev_user"])["User"].get("PermissionsBoundary")
    out.append(("service user has a permission boundary", bool(boundary), str(boundary)))

    world = []
    for sg in ctx.admin("ec2").describe_security_groups()["SecurityGroups"]:
        for p in sg.get("IpPermissions", []):
            if any(x.get("CidrIp") == "0.0.0.0/0" for x in p.get("IpRanges", [])):
                lo, hi = p.get("FromPort", 0), p.get("ToPort", 65535)
                if p.get("IpProtocol") == "-1" or lo <= 22 <= hi:
                    world.append(sg["GroupName"])
    out.append(("no security group open to the world on SSH", not world, str(sorted(set(world)) or "none")))

    rot = ctx.admin("kms").get_key_rotation_status(KeyId=r["kms_key_id"])["KeyRotationEnabled"]
    out.append(("data key rotation enabled", bool(rot), f"rotation={rot}"))

    trails = ctx.admin("cloudtrail").describe_trails(trailNameList=[r["trail_name"]])["trailList"]
    t = trails[0] if trails else {}
    ok = bool(t.get("IsMultiRegionTrail")) and bool(t.get("LogFileValidationEnabled"))
    out.append(("trail is multi-region with validation", ok, f"multi={t.get('IsMultiRegionTrail')} validation={t.get('LogFileValidationEnabled')}"))

    if r.get("instance_id"):
        inst = ctx.admin("ec2").describe_instances(InstanceIds=[r["instance_id"]])["Reservations"][0]["Instances"][0]
        tokens = inst.get("MetadataOptions", {}).get("HttpTokens")
        out.append(("instance requires IMDSv2", tokens == "required", f"HttpTokens={tokens}"))
    return out


def main() -> int:
    path = HERE.parent / "build" / "range" / "targets.json"
    if not path.exists():
        print("run `make range-up` first", file=sys.stderr)
        return 1
    targets = json.loads(path.read_text())
    for name in ("purple", "hardened"):
        t = targets[name]
        ctx = Context(Target(name, t["account_id"], t["hardened"], t["resources"], t["credentials"]),
                      ENDPOINT, "us-east-1", "posture")
        results = checks(ctx)
        passed = sum(ok for _, ok, _ in results)
        print(f"\n== {name} ({t['account_id']}): {passed} of {len(results)} posture checks pass")
        for label, ok, detail in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {label}  [{detail}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())