# AegisCloud spike report

Generated: 2026-10-28T20:06:23Z  |  Updated: 2026-10-30  |  Endpoint: http://localhost:4566

## Spike results (2026-10-28)

| Probe | Result | Notes |
|---|---|---|
| apply:organizations | PASS | |
| apply:logging | PASS | |
| apply:config | PASS | |
| apply:guardduty | FAIL | Terraform error; service not supported on this tier (HTTP 501) |
| apply:securityhub | FAIL | Terraform error; service not supported on this tier (HTTP 501) |
| apply:eventing | PASS | |
| api:multi-account-sts | PASS | 12-digit access key becomes the account ID |
| api:org-describe | PASS | |
| api:scp-listed | PASS | SCPs can be created, listed and attached |
| api:trail-status | PASS | |
| api:trail-lookup-events | PASS | |
| api:trail-delivers-to-s3 | PASS | Refined below: partial |
| api:config-recording | PASS | |
| api:config-rule | PASS | Rule definitions stored only |
| api:config-compliance | FAIL | `GetComplianceSummaryByConfigRule` returns InternalFailure |
| api:guardduty-detector | EMPTY | Call worked but output did not match `/^[a-z0-9]{10,}/` (stub?) |
| api:securityhub-hub | FAIL | `DescribeHub`: InternalFailure, service not supported |
| api:securityhub-standards | FAIL | `GetEnabledStandards`: InternalFailure, service not supported |
| api:securityhub-findings | FAIL | `GetFindings`: InternalFailure, service not supported |
| api:eventbridge-to-sqs | PASS | Round trip works |

## Stage 1 follow-up findings (2026-10-30)

| Probe | Result | Notes |
|---|---|---|
| scp:enforcement-stop-logging | NOT ENFORCED | Member account `580120752967` in the `workloads` OU with `protect-logging` attached (plus `deny-leave-org`, `region-lock`, `deny-public-s3-acls`, `FullAWSAccess`). `cloudtrail stop-logging` succeeded; `get-trail-status` returned `IsLogging=false` |
| scp:enforcement-delete-trail | NOT ENFORCED | `cloudtrail delete-trail` also succeeded under the same SCP |
| scp:deny-leave-org | UNTESTABLE | `organizations leave-organization` returns InternalFailure: operation not supported by LocalStack. The SCP was never evaluated |
| org:member-account-id | GENERATED | `create-account` returned a generated ID (`580120752967`), not a chosen one. It works as an access key (`sts get-caller-identity` returns it), so `create_member_accounts` is usable |
| api:trail-delivers-to-s3 (refined) | PARTIAL | The `AWSLogs/<account>/CloudTrail/` prefix was created in the bucket. Full log-file delivery was not verified |
| ci:gates-block-insecure-pr | PASS | Demo PR (public bucket + SSH open to the world): Checkov failed 4 resources, Conftest raised 7 violations (AEG-S3-001, AEG-NET-001, AEG-NET-003). All failures came from the demo file only |
| iam:enforcement | PENDING | `ENFORCE_IAM=1` test (section 7.2 of STAGE1.md) not yet run |

### Notes
- The SCP tests were run as the member account's root identity. Real AWS applies SCPs to member-account root users, so this is a LocalStack limitation, not an SCP error.
- CloudTrail trail names must be at least 3 characters. The guide's example name `t1` fails.
- The conclusion rests on two independent unconditional denies (`StopLogging`, `DeleteTrail`), both bypassed.

## What this means for the project
- SCPs are real-AWS-correct code in the repo, not a lab control. "Prevented by SCP" cannot be claimed in Stage 2.
- Preventive control in the lab comes from the CI gates (Checkov, OPA, `terraform test`), which block insecure code before it is deployed.
- Detective control comes from the runtime checks (`compliance_score.py`) and, from Stage 3, from the own detection engine (ADR-0002).
- Whether IAM policies and permission boundaries are testable as runtime preventive controls depends on the pending `ENFORCE_IAM` result.

## How to read this
- **PASS** on apply AND behaviour: rely on LocalStack for this service.
- **PASS** on apply but **EMPTY/FAIL** on behaviour: the resource is a stub. Build your own logic (Wazuh rules, Lambda checks) and document it as a LocalStack limitation.
- **FAIL** on apply: check `spike/logs/<name>.log`. Often a provider argument issue, not a missing service.
- **NOT ENFORCED / UNTESTABLE**: the API accepts the configuration but does not evaluate it, or does not implement the operation. Record it in `docs/localstack-limitations.md`.
- **SCPs are stored and attachable but not enforced** (see the follow-up above). The management account is exempt from SCPs in real AWS, so the Stage 1 test used a member account.