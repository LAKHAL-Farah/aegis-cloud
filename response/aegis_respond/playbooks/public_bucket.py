"""Playbook: an S3 bucket was made public. Turn Block Public Access back on and reset a public ACL.

Rollback is deliberately NOT automated: re-publishing a bucket is a decision for a person."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..incident import Incident
from ..policy import ResponsePolicy
from .base import Plan, Playbook, PlaybookRefusal, Step

ALL_ON = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
PUBLIC_GROUPS = ("AllUsers", "AuthenticatedUsers")


def _bpa(s3, bucket: str) -> dict | None:
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


def _public_grants(s3, bucket: str) -> list[str]:
    out = []
    for g in s3.get_bucket_acl(Bucket=bucket).get("Grants", []):
        grantee = g.get("Grantee", {})
        uri = str(grantee.get("URI", ""))
        if grantee.get("Type") == "Group" and uri.rsplit("/", 1)[-1] in PUBLIC_GROUPS:
            out.append(f"{uri.rsplit('/', 1)[-1]}:{g.get('Permission')}")
    return out


class PublicBucket(Playbook):
    id = "public_bucket"
    title = "Public bucket"

    def plan(self, inc: Incident, clients, policy: ResponsePolicy) -> Plan:
        bucket = inc.resource_id
        if not bucket or bucket == "unknown":
            raise PlaybookRefusal("the finding does not name a bucket")
        s3 = clients.get("s3")
        try:
            before, grants = _bpa(s3, bucket), _public_grants(s3, bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchBucket", "404"):
                raise PlaybookRefusal(f"bucket {bucket} no longer exists") from None
            raise
        actions, summary = [], []
        if before != ALL_ON:
            actions.append({"op": "block_public_access"})
            summary.append(f"Turn on all four Block Public Access settings for {bucket}")
        if grants:
            actions.append({"op": "reset_acl"})
            summary.append(f"Reset the ACL of {bucket} to private (removes {', '.join(grants)})")
        if not actions:
            summary = [f"Nothing to do: {bucket} is already private"]
        return Plan(summary, {"bucket": bucket, "previous_block_public_access": before, "public_grants": grants},
                    {"bucket": bucket, "actions": actions})

    def contain(self, inc: Incident, clients, plan: Plan, policy: ResponsePolicy) -> list[Step]:
        s3, bucket, steps = clients.get("s3"), plan.targets["bucket"], []
        for act in plan.targets["actions"]:
            try:
                if act["op"] == "block_public_access":
                    s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=ALL_ON)
                    steps.append(Step("block_public_access", True, "Block Public Access is on", {"bucket": bucket}))
                elif act["op"] == "reset_acl":
                    s3.put_bucket_acl(Bucket=bucket, ACL="private")
                    steps.append(Step("reset_acl", True, "ACL reset to private", {"bucket": bucket}))
            except ClientError as exc:
                steps.append(Step(act["op"], False, exc.response["Error"]["Code"]))
        return steps

    def verify(self, inc: Incident, clients, plan: Plan) -> Step:
        s3, bucket = clients.get("s3"), plan.targets["bucket"]
        problems = []
        if _bpa(s3, bucket) != ALL_ON:
            problems.append("Block Public Access is not fully on")
        if _public_grants(s3, bucket):
            problems.append("a public ACL grant remains")
        return Step("verify", not problems, "bucket is private" if not problems else "; ".join(problems))

    def rollback(self, clients, records: list[dict]) -> list[Step]:
        return [Step("rollback", False, "not automated: making a bucket public again is a human decision")]
