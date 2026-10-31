# AegisCloud spike report

Generated: 2026-10-28T20:06:23Z  |  Updated: 2026-10-31  |  Endpoint: http://localhost:4566

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
| scp:enforcement-stop-logging | ~~NOT ENFORCED~~ **SUPERSEDED 2026-10-31** | Member account `580120752967` in the `workloads` OU with `protect-logging` attached. `stop-logging` succeeded. Ran while `iam:enforcement` was still PENDING, so `ENFORCE_IAM=1` was probably not active (see Stage 2 findings) |
| scp:enforcement-delete-trail | ~~NOT ENFORCED~~ **SUPERSEDED 2026-10-31** | Same conditions as above. Not re-tested in Stage 2 (S04 covers `StopLogging` only) |
| scp:deny-leave-org | UNTESTABLE | `organizations leave-organization` returns InternalFailure: operation not supported by LocalStack. The SCP was never evaluated |
| org:member-account-id | GENERATED | `create-account` returned a generated ID (`580120752967`), not a chosen one. It works as an access key (`sts get-caller-identity` returns it), so `create_member_accounts` is usable |
| api:trail-delivers-to-s3 (refined) | PARTIAL | The `AWSLogs/<account>/CloudTrail/` prefix was created in the bucket. Full log-file delivery was not verified |
| ci:gates-block-insecure-pr | PASS | Demo PR (public bucket + SSH open to the world): Checkov failed 4 resources, Conftest raised 7 violations (AEG-S3-001, AEG-NET-001, AEG-NET-003). All failures came from the demo file only |
| iam:enforcement | ~~PENDING~~ **SUPERSEDED 2026-10-31** | See Stage 2 findings |

## Stage 2 findings (2026-10-31)

Run with `ENFORCE_IAM=1`, hardened twin = Organizations member account `402528835445` under OU `workloads`. Evidence: `docs/evidence/scorecards/baseline.*` and `as-root.*`.

| Probe | Result | Notes |
|---|---|---|
| iam:enforcement | PASS | Identity-based policies are evaluated: Stage 2 denials appear for `dev-svc` and `intern` on the hardened twin |
| iam:permission-boundary | ENFORCED | S03: `dev-svc` is denied `iam:CreateUser` (explicit Deny in the boundary) and the same call succeeds as account root (`as-root` run). S09: `intern` is denied `iam:CreatePolicyVersion` although its own policy allows it, so only the boundary can have denied it (`CreatePolicyVersion` is not in the boundary's Allow list) |
| iam:denial-message-wording | LIMITATION | For boundary denials LocalStack says "no identity-based policy allows ...", never "permissions boundary". The scorer labelled S03 and S09 as `IAM policy`. The correct layer is the boundary. Scorecards left as generated |
| scp:enforcement-stop-logging | ENFORCED (with `ENFORCE_IAM=1`) | S04 on hardened is denied with an SCP message. It is denied as account root too, and the `prevented_by` value is identical in `baseline` and `as-root`. The boundary does not apply to root, so the SCP is the only layer that can explain the root denial. Supersedes the 2026-10-30 row |
| scp:enforcement-cause | PROBABLE | The 2026-10-30 test ran before `ENFORCE_IAM` was verified, which most likely explains the flip. Not isolated by a controlled on/off test |
| scp:deny-public-s3-acls | NOT EFFECTIVE (S07) | `PutPublicAccessBlock` and `PutBucketAcl` both succeeded on hardened, and the boundary allows `s3:*`. Cause **PENDING**: (a) SCP does not cover `PutPublicAccessBlock`, (b) LocalStack does not evaluate the `s3:x-amz-acl` condition key. Check the SCP JSON and run `put-bucket-acl --acl public-read` by hand |
| ec2:run-instances-missing-ami | LIMITATION | `aws_instance` apply failed with `collecting instance settings: couldn't find resource` because `ami-ff0fea8310f3` does not exist in this LocalStack version. `ami-03cf127a` works and is now the default |
| cloudtrail:lookup-StopLogging | PENDING | S04 telemetry on purple is `NONE`, and `lookup-events` returns 0 events for `StopLogging` after the run. Manual stop/start test not yet run, so cause is unknown (event dropped while the trail is off, or not recorded at all) |
| cloudtrail:lookup-S09 | PARTIAL | `CreatePolicyVersion` is probably recorded, `SetDefaultPolicyVersion` probably is not, since `SetAsDefault=True` folds both into one call. Not verified |
| cloudtrail:s3-data-events | UNVERIFIED | S02 is a data event, not visible via `lookup-events`. The trail's S3 destination was not inspected |
| runner:as-root-s09 | SCENARIO LIMITATION | S09 uses the `intern` identity, so `--as-root` does not change it. The boundary document is the evidence for S09 |

### Prevention coverage on the hardened twin (baseline)

| Result | Scenarios | Layer |
|---|---|---|
| Prevented | S03, S09 | Permission boundary |
| Prevented | S04 | SCP (and the boundary also denies `StopLogging`) |
| Not prevented | S01, S02, S05, S06, S07, S08, S10, S11, S12 | The boundary allows `s3:*`, `kms:*`, `secretsmanager:*`, `ec2:*`, `iam:Get*`, `iam:List*`; its explicit denies cover only identity escalation and audit tampering |

Detected: 0 of 12. Prevented on hardened: 3 of 12.

### Notes
- The 2026-10-30 SCP tests were run as the member account's root identity. Real AWS applies SCPs to member-account root users, and with IAM enforcement on, LocalStack now does too (S04, `as-root`).
- CloudTrail trail names must be at least 3 characters. The guide's example name `t1` fails.
- The hardened trail is under `protect-logging`, so Terraform cannot reconfigure or delete it. The clean teardown is `make reset`.
- The repo lives on `/mnt/c` (NTFS), where the `common.tf` symlinks did not work. The range roots hold copies of `terraform/live/_shared/common.tf`.
- Pin the LocalStack image version here once fixed: `<tag>`.

## What this means for the project
- **SCP prevention can be claimed only when `ENFORCE_IAM=1` is on, and only for conditions that were tested.** `StopLogging` is confirmed. The `deny-public-s3-acls` statement is not (S07), and `DeleteTrail` and `deny-leave-org` are untested or untestable.
- **Permission boundaries are testable as a runtime preventive control.** Their denial messages cannot be used to tell the layer apart, so isolate layers with the `--as-root` comparison or by detaching the boundary.
- Preventive control also comes from the CI gates (Checkov, OPA, `terraform test`), which block insecure code before it is deployed.
- Detective control comes from the runtime checks (`compliance_score.py`) and, from Stage 3, from the own detection engine (ADR-0002).
- Do not claim `StopLogging` was "recorded in CloudTrail" until the pending lookup test is resolved. Count only scenarios with telemetry `FULL`.
- A hidden setting (`ENFORCE_IAM`) flipped the SCP result between two runs. Record the setting alongside every enforcement claim.

## How to read this
- **PASS** on apply AND behaviour: rely on LocalStack for this service.
- **PASS** on apply but **EMPTY/FAIL** on behaviour: the resource is a stub. Build your own logic (Wazuh rules, Lambda checks) and document it as a LocalStack limitation.
- **FAIL** on apply: check `spike/logs/<name>.log`. Often a provider argument issue, not a missing service.
- **NOT ENFORCED / UNTESTABLE**: the API accepts the configuration but does not evaluate it, or does not implement the operation. Record it in `docs/localstack-limitations.md`.
- **ENFORCED**: a denial was observed and attributed to that layer by a controlled comparison.
- **PENDING / UNVERIFIED**: no evidence yet. Do not cite in the post.
- **SCPs are stored and attachable.** They are evaluated only with `ENFORCE_IAM=1`, and not every condition key is verified. The management account is exempt from SCPs in real AWS, so tests use a member account.