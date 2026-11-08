"""CloudTrail event names -> IAM actions, and the action universe used to size what a policy grants.

Two honest approximations live here, and the report repeats both:
* An event name is usually the IAM action name. The exceptions that matter for a first version are in SPECIAL; anything
  else is kept 1:1 and counted as `unverified`.
* The "universe" of actions behind a wildcard is taken from botocore's operation names. That is close to the IAM action
  list for most services, not identical (s3 is the biggest gap). It sizes a wildcard; it does not authorise anything."""
from __future__ import annotations

PREFIX = {"monitoring": "cloudwatch", "email": "ses", "tagging": "tag", "sso-directory": "sso-directory",
          "kinesisanalytics": "kinesisanalytics", "runtime.sagemaker": "sagemaker"}
NO_PERMISSION = {("sts", "GetCallerIdentity"), ("signin", "ConsoleLogin"), ("sts", "GetSessionToken")}
SPECIAL = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets", ("s3", "HeadBucket"): "s3:ListBucket", ("s3", "HeadObject"): "s3:GetObject",
    ("s3", "ListObjects"): "s3:ListBucket", ("s3", "ListObjectsV2"): "s3:ListBucket", ("s3", "ListObjectVersions"): "s3:ListBucketVersions",
    ("s3", "DeleteObjects"): "s3:DeleteObject", ("s3", "CreateMultipartUpload"): "s3:PutObject", ("s3", "UploadPart"): "s3:PutObject",
    ("s3", "CompleteMultipartUpload"): "s3:PutObject", ("s3", "CopyObject"): "s3:PutObject", ("s3", "GetBucketLocation"): "s3:GetBucketLocation",
}
S3_OBJECT = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:GetObjectAcl", "s3:PutObjectAcl", "s3:GetObjectVersion",
             "s3:DeleteObjectVersion", "s3:GetObjectTagging", "s3:PutObjectTagging"}

# Observed, but never turned into a permission automatically: these are the calls that abuse a stolen credential (and a few an
# administrator does). Left out unless --keep-sensitive says a person looked at them.
SENSITIVE = (
    "iam:Create*", "iam:Attach*", "iam:Put*", "iam:Add*", "iam:Update*", "iam:SetDefaultPolicyVersion", "iam:Delete*",
    "iam:PassRole", "cloudtrail:Stop*", "cloudtrail:Delete*", "cloudtrail:Update*", "config:Stop*", "config:Delete*",
    "kms:ScheduleKeyDeletion", "kms:Disable*", "kms:Put*", "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutPublicAccessBlock",
    "s3:DeletePublicAccessBlock", "s3:PutBucketVersioning", "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress",
    "organizations:*", "secretsmanager:PutSecretValue", "secretsmanager:DeleteSecret",
)


def to_action(event_source: str, event_name: str) -> tuple[str | None, str]:
    """(action | None, how). how: exact | special | none (needs no permission) | unverified."""
    svc = event_source.removesuffix(".amazonaws.com")
    if (svc, event_name) in NO_PERMISSION:
        return None, "none"
    if (svc, event_name) in SPECIAL:
        return SPECIAL[(svc, event_name)], "special"
    prefix = PREFIX.get(svc, svc)
    return f"{prefix}:{event_name}", "unverified" if prefix in ("s3",) else "exact"


class Universe:
    """All actions of the services botocore knows. Slow to build once (loads every service model), then cached."""

    _SHARED: dict[str, frozenset] = {}      # botocore's models do not change within a process, so every Universe shares one cache

    def __init__(self):
        self._cache = Universe._SHARED

    def prefixes(self) -> list[str]:
        from botocore.session import get_session
        return sorted(get_session().get_available_services())

    def actions(self, prefix: str) -> frozenset:
        if prefix not in self._cache:
            try:
                from botocore.session import get_session
                model = get_session().get_service_model(prefix)
                ops = {f"{prefix}:{op}" for op in model.operation_names}
                # IAM names that differ from the operation name (s3:ListAllMyBuckets is the operation ListBuckets) are added,
                # or a policy that uses them would be counted as granting nothing.
                ops |= {a for a in SPECIAL.values() if a.startswith(prefix + ":")}
                self._cache[prefix] = frozenset(ops)
            except Exception:  # noqa: BLE001 - an unknown prefix has no known actions
                self._cache[prefix] = frozenset()
        return self._cache[prefix]

    def everything(self) -> frozenset:
        out: set = set()                    # the per-service lookups are cached and shared; the union is cheap
        for p in self.prefixes():
            out |= self.actions(p)
        return frozenset(out)
