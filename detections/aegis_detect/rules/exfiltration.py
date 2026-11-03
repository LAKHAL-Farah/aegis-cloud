from __future__ import annotations

import json

from ..util import ACCOUNT_RE, as_obj, as_list, deep_find, flat_text, is_false
from .base import Rule, register


def _policy_doc(request) -> dict:
    for key in ("bucketPolicy", "policy", "policyDocument", "Policy"):
        for cand in deep_find(request, key):
            doc = as_obj(cand)
            if isinstance(doc, dict) and "Statement" in doc:
                return doc
    return {}


def _principals(statement: dict) -> list[str]:
    p = statement.get("Principal", statement.get("principal"))
    if p == "*":
        return ["*"]
    if isinstance(p, dict):
        out = []
        for v in p.values():
            out += [str(x) for x in as_list(v)]
        return out
    return [str(x) for x in as_list(p)]


def _is_cloudtrail_log_read(ev) -> bool:
    """Reading CloudTrail's own log files is what a log consumer (our detector) does. LocalStack records those
    reads, so without this the detector would alert on itself. Category is NOT checked: LocalStack labels some
    GetObject records 'Management' (docs/evidence/telemetry-probe.md)."""
    key = str((deep_find(ev.request, "key") or [""])[0])
    return key.startswith("AWSLogs/") and "/CloudTrail/" in key


@register
class BucketPolicyExternalPrincipal(Rule):
    id = "AEG-EXFIL-001"
    title = "Bucket policy grants access outside the account"
    description = "A bucket policy now allows a principal from another account (or everyone)."
    technique, tactic, severity = "T1537", "Exfiltration", "high"
    resource_type = "AwsS3Bucket"
    cooldown = 30

    def evaluate(self, ev, window, policy):
        if ev.name != "PutBucketPolicy" or not ev.succeeded:
            return []
        doc = _policy_doc(ev.request)
        if not doc:   # the log did not record a readable policy body (LocalStack records "")
            bucket = str((deep_find(ev.request, "bucketName") or ["unknown"])[0])
            return [self.detection(ev, resource_id=bucket, severity="medium", dedup=bucket,
                                   title=f"Bucket policy changed, body not recorded so the principal cannot be checked: {bucket}")]
        trusted = {ev.account_id, *[str(a) for a in policy.trusted_accounts]}
        foreign = []
        for st in as_list(doc.get("Statement")):
            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                continue
            for pr in _principals(st):
                if pr == "*":
                    foreign.append("*")
                else:
                    foreign += [a for a in ACCOUNT_RE.findall(pr) if a not in trusted]
        if not foreign:
            return []
        bucket = str((deep_find(ev.request, "bucketName") or ["unknown"])[0])
        sev = "critical" if "*" in foreign else "high"
        return [self.detection(ev, resource_id=bucket, severity=sev, dedup=bucket,
                               title=f"{self.title}: {bucket} -> {sorted(set(foreign))[0]}")]


@register
class BucketMadePublic(Rule):
    id = "AEG-EXFIL-002"
    title = "Bucket exposed to the public"
    description = "Block Public Access was relaxed or removed, or an ACL grants access to everyone."
    technique, tactic, severity = "T1530", "Collection", "high"
    resource_type = "AwsS3Bucket"
    cooldown = 60

    def evaluate(self, ev, window, policy):
        if not ev.succeeded or ev.service != "s3.amazonaws.com":
            return []
        reason = None
        if ev.name == "PutBucketAcl":
            text = flat_text(ev.request)
            if any(t in text for t in ("allusers", "authenticatedusers", "public-read")):
                reason = "public ACL"
        elif ev.name == "DeletePublicAccessBlock":
            reason = "Block Public Access removed"
        elif ev.name == "PutPublicAccessBlock":
            flags = deep_find(ev.request, "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                              "RestrictPublicBuckets")
            if any(is_false(f) for f in flags):
                reason = "Block Public Access relaxed"
        if not reason:
            return []
        bucket = str((deep_find(ev.request, "bucketName") or ["unknown"])[0])
        return [self.detection(ev, resource_id=bucket, dedup=bucket, title=f"{self.title}: {bucket} ({reason})")]


@register
class GetObjectBurst(Rule):
    id = "AEG-EXFIL-003"
    title = "Bulk S3 object download"
    description = ("Many distinct objects read from one bucket by one identity in a short time. "
                   "Needs CloudTrail S3 data events; without them this rule is blind.")
    technique, tactic, severity = "T1530", "Collection", "high"
    resource_type = "AwsS3Bucket"
    cooldown = 120

    def evaluate(self, ev, window, policy):
        if ev.name != "GetObject" or _is_cloudtrail_log_read(ev):
            return []
        bucket = str((deep_find(ev.request, "bucketName") or ["unknown"])[0])

        def same(e):
            return (e.name == "GetObject" and not _is_cloudtrail_log_read(e) and e.principal == ev.principal and
                    str((deep_find(e.request, "bucketName") or ["unknown"])[0]) == bucket)
        hits = window.recent(ev, policy.threshold("getobject_window_s", 60), same)
        keys = {str((deep_find(e.request, "key") or [e.id])[0]) for e in hits}
        if len(keys) >= policy.threshold("getobject_burst", 10):
            return [self.detection(ev, resource_id=bucket, dedup=bucket, evidence=hits,
                                   title=f"{self.title}: {len(keys)} objects from {bucket}")]
        return []