# Does this run on real AWS?

**Short answer: not tested, and not as-is.** Nothing in this repository has been applied to a real AWS account. The modules are
written to be portable, and that is the part most likely to hold, but the live roots, the state backend and the detection and
response tools are wired to LocalStack. This page lists what would have to change and what would behave differently. It
exists so the README does not claim more than has been checked.

Checked on 2026-11-06 against the `stage5/operate` branch plus Stage 6 and 7.

## What is likely portable

* `terraform/modules/*` use ordinary AWS resources. Where LocalStack needed a workaround the module exposes a variable instead of
  hard-coding it: `detailed_monitoring` in `compute`, interface endpoints in `network`, the organization-wide trail and an own
  KMS key in `logging`, `enable_backup` and `enable_patching` at the workload root. On real AWS these would be set the other way.
* Policies (`policies/scp/`, `policies/opa/`) and the CI gates (fmt, validate, tflint, Checkov, Conftest, `terraform test`)
  do not depend on LocalStack. They run on plans.
* The Python tools take their endpoint from configuration. Pointing them at real AWS means removing it, which has not been done.

## What is LocalStack-specific today

| Where | What is hard-coded | What a real run needs |
| --- | --- | --- |
| `terraform/live/_shared/common.tf` | Provider with every service endpoint set to the LocalStack URL, a static access key that doubles as the account id, `secret_key = "test"`, and `skip_*` validation flags | A provider with no custom endpoints, real credentials or an assumed role per account, and validation switched back on. There is no variable for this today: it is a code change, not a flag |
| `terraform/live/*/backend.tf` | State in an S3 bucket on LocalStack with test credentials | A real bucket, real credentials and locking |
| Account ids | `terraform/live/_shared/accounts.auto.tfvars` holds invented 12-digit ids (ADR-0001) | Real ids from AWS Organizations, and cross-account roles instead of access keys that become ids |
| `organization` module | Notes that member account ids may not match the keys on LocalStack | Accounts created by Organizations get ids you do not choose, so everything keyed by id must follow |
| Managed security | ADR-0004 describes a `managed-security` module behind `enable_managed_security`. **That module does not exist on this branch**: a search of the repository finds the name only in ADR-0004. GuardDuty and Security Hub are therefore not defined anywhere | Write the module, then apply it on real AWS. The ADR carries an amendment saying so |
| Detector, responder, Sentinel | Read an endpoint from configuration; test accounts are the fake ids | Real credentials, real regions, and a check of every assumption about log delivery timing |

## What would behave differently on real AWS

* **Config rule evaluation exists.** LocalStack stores rule definitions but does not evaluate them (`docs/localstack-limitations.md`),
  which is why the compliance score is computed by this repository (ADR-0003). On AWS, Config evaluates, and ADR-0005 still says
  remediation is not triggered from Config.
* **CloudTrail records the real caller.** On LocalStack every call is logged with the same user agent and address, which is why
  S08 cannot be scored (ADR-0014). On AWS it could be, and it would probably also catch false positives the lab never sees.
* **SCPs apply as documented.** On LocalStack they are enforced only with `ENFORCE_IAM=1`, and only some conditions were tested.
  IAM Sentinel treats an SCP deny as a plain deny and ignores conditions, so its picture would be incomplete for real
  organizations.
* **Log delivery latency will differ.** Stage 4's measured attack-to-contained time is dominated by delivery to the log bucket
  (`docs/lessons-learned.md`). The real number is unknown.
* **GuardDuty and Security Hub exist**, and findings in ASFF from this repository could feed Security Hub (ADR-0002). Not tried.
* **Cost.** NAT gateways, KMS keys, the Config recorder, CloudTrail and any Lambda are billed. The lab spends nothing, so no cost
  figure here is measured.

## If someone does a first real run

1. Use a throwaway account in a new organization. Do not point this at an account that holds anything.
2. Start with `terraform plan` only, using a provider block without endpoints. Read the plan before anything is applied.
3. Apply one root at a time (management and log-archive first, because everything else logs to them) and record every surprise in `docs/localstack-limitations.md`
   under a new heading ("real AWS"), the way the Stage 2 surprises were recorded.
4. Re-run the Stage 2 scorecard before claiming any number carries over. None of them is evidence about real AWS.
