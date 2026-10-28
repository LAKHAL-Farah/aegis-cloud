# Stage 1: SecureLanding (weeks 1-3)

**Goal:** a CIS-mapped Terraform landing zone where an insecure PR fails CI and a compliance score is generated.

## Repo layout

```
aegiscloud/
├── README.md
├── Makefile                      up / down / spike / fmt / plan / test
├── docker-compose.yml            LocalStack for AWS
├── spike/                        feasibility spike (delete or archive after Stage 1 starts)
├── terraform/
│   ├── modules/
│   │   ├── organization/         Org, OUs, SCPs, member accounts
│   │   ├── network/              3-tier VPC, NACLs, SGs, VPC endpoints, flow logs
│   │   ├── iam-baseline/         password policy, permission boundaries, roles, no IAM users
│   │   ├── logging/              CloudTrail (org trail), log-archive bucket, KMS, access logs
│   │   ├── config-rules/         Config recorder + CIS-style managed rules
│   │   ├── data/                 KMS-encrypted S3 with BPA, versioning, lifecycle
│   │   └── compute/              private instances, SSM role, no public IPs
│   ├── live/
│   │   ├── management/           org, SCPs, org trail
│   │   ├── log-archive/          central log bucket (account 2222...)
│   │   ├── security/             Config aggregator, later Wazuh/ELK + detection (account 3333...)
│   │   └── workload/             network, data, compute (account 4444...)
│   └── tests/                    terraform test (.tftest.hcl) per module
├── policies/
│   ├── opa/                      Conftest rules on the plan JSON
│   ├── scp/                      SCP JSON, kept out of HCL so they are lintable
│   └── checkov/                  custom Checkov checks + skip justifications
├── scripts/
│   ├── compliance_score.py       Config + plan results -> score (JSON + markdown)
│   └── drift_check.sh            scheduled `terraform plan -detailed-exitcode`
├── docs/
│   ├── STAGE1.md
│   ├── cis-mapping.md            control -> Terraform resource -> check
│   ├── localstack-limitations.md filled from spike-report.md
│   ├── threat-model.md
│   └── adr/                      0001-multi-account-via-12-digit-keys.md ...
└── .github/workflows/
    ├── terraform-ci.yml          fmt, validate, tflint, checkov, conftest, terraform test
    ├── drift.yml                 nightly plan, opens an issue on drift
    └── infracost.yml             cost comment on PRs
```

## Multi-account on LocalStack
LocalStack treats a 12-digit access key as the account ID. Use one provider alias per account:

```hcl
provider "aws" {
  alias      = "log_archive"
  access_key = "222222222222"
  secret_key = "test"
  # ...same endpoints block as spike/providers.tf
}
```
The spike verifies this works (`api:multi-account-sts`). Record it as ADR-0001.

## Module build order
| # | Module | Why first | CI proof |
|---|---|---|---|
| 1 | `organization` | SCPs are the preventive layer | `terraform test` asserts SCP content |
| 2 | `logging` | Everything later needs the log archive | Checkov: encryption, versioning, BPA |
| 3 | `config-rules` | Produces the compliance score | rule list equals cis-mapping.md |
| 4 | `iam-baseline` | Least privilege, boundaries | OPA: no `*:*`, no inline user policies |
| 5 | `network` | Segmentation | OPA: no 0.0.0.0/0 ingress except documented |
| 6 | `data`, `compute` | Workloads to attack in Stage 2 | Checkov clean |

## CIS mapping template (`docs/cis-mapping.md`)
| CIS control | Requirement | Terraform resource | Preventive check | Detective check |
|---|---|---|---|---|
| 1.x | Root MFA | (Config rule) `root-account-mfa-enabled` | n/a | Config |
| 2.1 | CloudTrail in all regions | `aws_cloudtrail.main` | Checkov CKV_AWS_67 | Config |
| 2.6 | S3 access logging on trail bucket | `aws_s3_bucket_logging` | Checkov | Config |
| 3.x | Monitoring filters/alarms | `aws_cloudwatch_log_metric_filter` | tflint | CloudWatch |
| 4.1 | No SG open to 0.0.0.0/0 on 22 | `aws_security_group` | OPA | Config |
| 5.x | Default VPC SG restricts all | `aws_default_security_group` | Checkov | Config |

Treat check IDs as starting points and verify them against your Checkov version.

## Week plan
- **Week 1:** LocalStack + spike, remote state (S3 backend on LocalStack), `organization` and `logging` modules, ADR-0001/0002, first CI (fmt, validate, tflint).
- **Week 2:** `config-rules`, `iam-baseline`, `network`; Checkov + Conftest gates; `terraform test` for each module.
- **Week 3:** `data`, `compute`; `compliance_score.py`; drift workflow; Infracost; CIS doc; the "blocked PR" demo.

## Definition of done
- [ ] `make up && terraform apply` builds all four accounts from scratch
- [ ] A PR adding a public bucket fails CI with a clear message (screenshot it)
- [ ] `scripts/compliance_score.py` prints N of M controls passing
- [ ] `docs/cis-mapping.md` complete, `docs/localstack-limitations.md` honest
- [ ] 5+ ADRs
- [ ] LinkedIn post 1 drafted: "I enforced N CIS controls as code. Here's the PR that got blocked."
