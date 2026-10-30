# CIS AWS Foundations Benchmark mapping

Numbering: CIS AWS Foundations Benchmark v1.4.0 (verify against the PDF you cite).
Machine-readable twin: `policies/cis_controls.json` (used by `scripts/compliance_score.py`).

| CIS | Requirement | Terraform resource | Preventive check | Detective check | Status |
| --- | --- | --- | --- | --- | --- |
| 1.5 | MFA on root account | Config rule `root-account-mfa-enabled` | n/a | not emulated on LocalStack | not evaluated |
| 1.8 | Password minimum length 14 | `aws_iam_account_password_policy.this` | `terraform test` (iam-baseline) | boto3 `password_policy_length` | enforced |
| 1.9 | Password reuse prevention 24 | `aws_iam_account_password_policy.this` | `terraform test` (iam-baseline) | boto3 `password_policy_reuse` | enforced |
| 1.12 | Unused credentials | Config rule `iam-user-unused-credentials-check` | n/a (no IAM users by design) | Config rule (stored only) | by design |
| 1.14 | Access keys rotated | Config rule `access-keys-rotated` | n/a (no IAM users by design) | Config rule (stored only) | by design |
| 1.16 | No full `*:*` policies | `aws_iam_policy.boundary` and roles | OPA AEG-IAM-001/002, Checkov CKV_AWS_62/63 | n/a | enforced |
| 2.1.2 | S3 denies HTTP | `secure-bucket` bucket policy | `terraform test` (secure-bucket) | Config rule `s3-bucket-ssl-requests-only` (stored only) | enforced |
| 2.1.5 | S3 Block Public Access | `aws_s3_bucket_public_access_block.this` | OPA AEG-S3-001, Checkov CKV_AWS_53-56, SCP `deny-public-s3-acls` | boto3 `s3_public_block` | enforced |
| 3.1 | CloudTrail in all regions | `aws_cloudtrail.main` | Checkov CKV_AWS_67, `terraform test` (logging) | boto3 `trail_multi_region` | enforced |
| 3.2 | Log file validation | `aws_cloudtrail.main` | Checkov CKV_AWS_36, `terraform test` | boto3 `trail_validation` | enforced |
| 3.4 | CloudTrail to CloudWatch Logs | planned | skipped CKV2_AWS_10 (justified) | planned | Stage 5 |
| 3.6 | S3 access logging on trail bucket | `module.archive` + `aws_s3_bucket_logging` | Checkov CKV_AWS_18 | boto3 `trail_bucket_logging` | enforced |
| 3.7 | Trail encrypted with KMS | `aws_cloudtrail.main.kms_key_id` | Checkov CKV_AWS_35, `terraform test` | boto3 `trail_kms` | enforced |
| 3.8 | CMK rotation | `aws_kms_key.*` | Checkov CKV_AWS_7, `terraform test` | boto3 `kms_rotation` | enforced |
| 3.9 | VPC flow logs | `aws_flow_log.this` | Checkov CKV2_AWS_11 | boto3 `vpc_flow_logs` | enforced |
| 4.x | Metric filters and alarms | `aws_cloudwatch_log_metric_filter` | tflint | CloudWatch alarms | Stage 5 |
| 5.1 | No NACL admin ports from world | `aws_network_acl_rule.this` | OPA AEG-NET-002, `terraform test` (network) | n/a | enforced |
| 5.2 | No SG admin ports from world | `aws_vpc_security_group_ingress_rule` | OPA AEG-NET-001/003, Checkov CKV_AWS_24/25 | boto3 `sg_admin_ports` | enforced |
| 5.3 | Default SG restricts all | `aws_default_security_group.this` | Checkov CKV2_AWS_12 | boto3 `default_sg_closed` | enforced |

## AWS Config rules declared (portability only, 15)

root-account-mfa-enabled, iam-password-policy, iam-user-unused-credentials-check, access-keys-rotated,
iam-no-admin-policies, s3-bucket-ssl-requests-only, s3-bucket-level-public-access-prohibited,
cloudtrail-enabled, cloud-trail-log-file-validation-enabled, s3-bucket-logging-enabled,
cloud-trail-encryption-enabled, cmk-backing-key-rotation-enabled, vpc-flow-logs-enabled,
restricted-ssh, vpc-default-security-group-closed.

The Config rules list must match `terraform/modules/config-rules` (a unit test asserts the count).