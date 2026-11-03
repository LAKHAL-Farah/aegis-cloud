from __future__ import annotations

from ..util import deep_find
from .base import Rule, register


@register
class KmsKeyDeletion(Rule):
    id = "AEG-IMPACT-001"
    title = "KMS key scheduled for deletion"
    description = "Deleting a customer-managed key makes everything encrypted under it unrecoverable."
    technique, tactic, severity = "T1485", "Impact", "critical"
    resource_type = "AwsKmsKey"
    cooldown = 30

    def evaluate(self, ev, window, policy):
        if ev.name != "ScheduleKeyDeletion" or not ev.succeeded:
            return []
        key = str((deep_find(ev.request, "keyId") or ["unknown"])[0])
        return [self.detection(ev, resource_id=key, dedup=key, title=f"{self.title}: {key}")]


@register
class VersioningSuspended(Rule):
    id = "AEG-IMPACT-002"
    title = "Bucket versioning suspended"
    description = "Suspending versioning removes the safety net that makes deletes recoverable."
    technique, tactic, severity = "T1490", "Impact", "high"
    resource_type = "AwsS3Bucket"
    cooldown = 60

    def evaluate(self, ev, window, policy):
        if ev.name != "PutBucketVersioning" or not ev.succeeded:
            return []
        status = [str(s).lower() for s in deep_find(ev.request, "status")]
        if "suspended" not in status:
            return []
        bucket = str((deep_find(ev.request, "bucketName") or ["unknown"])[0])
        return [self.detection(ev, resource_id=bucket, dedup=bucket, title=f"{self.title}: {bucket}")]


@register
class DeleteBurst(Rule):
    id = "AEG-IMPACT-003"
    title = "Bulk S3 object deletion"
    description = "Many objects deleted by one identity in a short time. Needs S3 data events."
    technique, tactic, severity = "T1485", "Impact", "critical"
    resource_type = "AwsS3Bucket"
    cooldown = 120

    def evaluate(self, ev, window, policy):
        if ev.name not in {"DeleteObject", "DeleteObjects"}:   # the category label is not trusted (LocalStack: always Management)
            return []
        hits = window.recent(ev, policy.threshold("delete_window_s", 60),
                             lambda e: e.name in {"DeleteObject", "DeleteObjects"} and e.principal == ev.principal)
        if len(hits) >= policy.threshold("delete_burst", 5):
            bucket = str((deep_find(ev.request, "bucketName") or ["unknown"])[0])
            return [self.detection(ev, resource_id=bucket, dedup=bucket, evidence=hits,
                                   title=f"{self.title}: {len(hits)} deletes in {bucket}")]
        return []