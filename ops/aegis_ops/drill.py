"""Backup and restore drill. A backup nobody has restored from is a hope, not a backup.

What it proves, using only S3 versioning (which LocalStack implements for real): objects written, then destroyed
the two ways an attacker destroys them (delete, and overwrite with garbage, the T1485/T1490 family that scenarios S10
and S12 attack), come back bit for bit, in a measured time (the RTO).

What it does NOT prove: the AWS Backup service. LocalStack stores its plans and vaults but this project does not
claim restores from them (docs/localstack-limitations.md, ADR-0017).
"""
from __future__ import annotations

import hashlib
import math
import os
import time
from dataclasses import dataclass, field

PREFIX = "aegis-drill/"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class DrillResult:
    objects: int
    restored: int
    verified: int
    mismatches: list = field(default_factory=list)
    rto_s: float = 0.0
    passed: bool = False

    def line(self) -> str:
        return (f"restore drill: {self.verified}/{self.objects} objects restored and verified bit for bit, "
                f"RTO {self.rto_s:.2f} s -> {'PASS' if self.passed else 'FAIL'}")


def newest_good_version(s3, bucket: str, key: str, cutoff: float) -> str | None:
    """Newest real version older than the incident. Delete markers and anything at or after the cutoff are skipped.
    S3 stamps whole seconds, so the cutoff is floored to one and callers must leave a full second between the last
    legitimate write and the incident (the drill does)."""
    cut = math.floor(cutoff)
    best, best_t = None, -1.0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        for v in page.get("Versions", []):
            if v["Key"] != key:
                continue
            t = v["LastModified"].timestamp()
            if t < cut and t > best_t:
                best, best_t = v["VersionId"], t
    return best


def restore_before(s3, bucket: str, keys: list[str], cutoff: float) -> tuple[int, list[str]]:
    """Copy each key's last good version back on top. Returns (restored, keys with no good version)."""
    restored, missing = 0, []
    for key in keys:
        vid = newest_good_version(s3, bucket, key, cutoff)
        if vid is None:
            missing.append(key)
            continue
        s3.copy_object(Bucket=bucket, Key=key, CopySource={"Bucket": bucket, "Key": key, "VersionId": vid})
        restored += 1
    return restored, missing


def run_drill(s3, bucket: str, *, n: int = 6, prefix: str = PREFIX, clock=time.time, sleep=time.sleep,
              settle_s: float = 1.1, keep: bool = False) -> DrillResult:
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    originals = {f"{prefix}obj-{i}.bin": os.urandom(256) for i in range(n)}
    for k, body in originals.items():
        s3.put_object(Bucket=bucket, Key=k, Body=body)
    sleep(settle_s)                               # a full second between the last good write and the incident
    cutoff = clock()
    # the disaster: the first half deleted, the second half overwritten with garbage
    keys = sorted(originals)
    for k in keys[: n // 2]:
        s3.delete_object(Bucket=bucket, Key=k)
    for k in keys[n // 2:]:
        s3.put_object(Bucket=bucket, Key=k, Body=b"ENCRYPTED-BY-ATTACKER")
    # the recovery, timed
    t0 = clock()
    restored, missing = restore_before(s3, bucket, keys, cutoff)
    mismatches = list(missing)
    verified = 0
    for k in keys:
        if k in missing:
            continue
        try:
            body = s3.get_object(Bucket=bucket, Key=k)["Body"].read()
        except Exception:  # noqa: BLE001
            mismatches.append(k)
            continue
        if _sha(body) == _sha(originals[k]):
            verified += 1
        else:
            mismatches.append(k)
    rto = clock() - t0
    if not keep:
        purge(s3, bucket, prefix)
    return DrillResult(n, restored, verified, sorted(set(mismatches)), rto, verified == n)


def purge(s3, bucket: str, prefix: str) -> int:
    """Remove every version and delete marker under the drill prefix (and only there)."""
    n = 0
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
            n += 1
    return n
