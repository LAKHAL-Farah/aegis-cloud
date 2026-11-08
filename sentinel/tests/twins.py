"""Build the two IAM twins the range uses (cloudpurple/terraform/modules/range-target and terraform/modules/iam-baseline)
through real boto3 calls against moto, then collect them with the real collector. The policy documents are copied from
those Terraform files, and test_twins_match_terraform.py fails if they drift apart."""
import json

import boto3

ACCT = "123456789012"          # moto's account id
BOUNDARY_NAME = "aegis-permission-boundary"
BOUNDARY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "AllowWorkloadServices", "Effect": "Allow", "Resource": "*",
         "Action": ["ec2:*", "s3:*", "kms:*", "logs:*", "cloudwatch:*", "ssm:*", "lambda:*", "events:*", "sns:*", "sqs:*",
                    "secretsmanager:*", "iam:Get*", "iam:List*", "iam:PassRole", "iam:CreateServiceLinkedRole"]},
        {"Sid": "DenyIdentityEscalation", "Effect": "Deny", "Resource": "*",
         "Action": ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:DeleteRolePermissionsBoundary",
                    "iam:DeleteUserPermissionsBoundary"]},
        {"Sid": "DenyAuditTampering", "Effect": "Deny", "Resource": "*",
         "Action": ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                    "config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder"]},
    ],
}
WILDCARD = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
INTERN = {"Version": "2012-10-17", "Statement": [
    {"Sid": "Basics", "Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
    {"Sid": "EditOwnPolicy", "Effect": "Allow",
     "Action": ["iam:CreatePolicyVersion", "iam:ListPolicyVersions", "iam:SetDefaultPolicyVersion"],
     "Resource": f"arn:aws:iam::{ACCT}:policy/intern-policy"}]}
ROOT_TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"},
                                                      "Action": "sts:AssumeRole"}]}
MFA_ROOT_TRUST = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "sts:AssumeRole",
    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}


def build_twin(iam, hardened: bool) -> None:
    boundary_arn = None
    if hardened:
        boundary_arn = iam.create_policy(PolicyName=BOUNDARY_NAME, PolicyDocument=json.dumps(BOUNDARY))["Policy"]["Arn"]
        # The two AWS-managed attachments are added to the snapshot in _collect_twin: asking moto to know AWS-managed
        # policies means loading its whole catalogue (a 4.7 MB module), which made every test start slow.
        iam.create_role(RoleName="aegis-break-glass-admin", AssumeRolePolicyDocument=json.dumps(MFA_ROOT_TRUST))
        iam.create_role(RoleName="aegis-deployer", AssumeRolePolicyDocument=json.dumps(ROOT_TRUST), PermissionsBoundary=boundary_arn)
    kw = {"PermissionsBoundary": boundary_arn} if boundary_arn else {}
    iam.create_user(UserName="dev-svc", **kw)
    iam.put_user_policy(UserName="dev-svc", PolicyName="dev-svc-wildcard", PolicyDocument=json.dumps(WILDCARD))
    iam.create_policy(PolicyName="intern-policy", PolicyDocument=json.dumps(INTERN))
    iam.create_user(UserName="intern", **kw)
    iam.attach_user_policy(UserName="intern", PolicyArn=f"arn:aws:iam::{ACCT}:policy/intern-policy")


_CACHE: dict = {}


def collect_twin(hardened: bool) -> dict:
    """Building a twin in moto takes about two seconds, so each is built once per run. Callers get their own copy."""
    import copy
    if hardened not in _CACHE:
        _CACHE[hardened] = _collect_twin(hardened)
    return copy.deepcopy(_CACHE[hardened])


def _collect_twin(hardened: bool) -> dict:
    from moto import mock_aws

    from aegis_sentinel import snapshot
    with mock_aws():
        iam = boto3.client("iam", region_name="us-east-1")
        build_twin(iam, hardened)
        snap = snapshot.collect(iam, ACCT)
    if hardened:
        from aegis_sentinel.snapshot import BUNDLED
        for role, pol in (("aegis-break-glass-admin", "AdministratorAccess"), ("aegis-deployer", "PowerUserAccess")):
            arn = f"arn:aws:iam::aws:policy/{pol}"
            snap["principals"][f"arn:aws:iam::{ACCT}:role/{role}"]["attached"].append(arn)
            snap["policies"][arn] = {"name": pol, "aws_managed": True, "bundled": True, "approximate": BUNDLED[arn]["approximate"],
                                     "doc": BUNDLED[arn]["doc"], "other_versions": []}
        # moto does not implement permission boundaries on users (put_user_permissions_boundary is missing and
        # create_user drops the argument), so the boundary is set on the collected snapshot. Roles are real.
        arn = f"arn:aws:iam::{ACCT}:policy/{BOUNDARY_NAME}"
        for p in snap["principals"].values():
            if p["kind"] == "user":
                p["boundary"] = arn
    return snap
