# AegisCloud

Terraform-built, CIS-mapped AWS landing zone that gets attacked on purpose, detects the attack, and responds automatically. Runs on LocalStack for AWS; the same Terraform targets real AWS by changing the provider endpoints (see ADR-0004).

> Portfolio / learning project. Simulated behaviour is labelled as simulated; see `docs/localstack-limitations.md`.

## Status

| Stage | State |
| --- | --- |
| 1. SecureLanding | in progress, see `docs/STAGE1.md` |
| 2. CloudPurple attack range | done, scorecards in `docs/evidence/scorecards/` |
| 3. Detection | done, scorecards in `docs/evidence/scorecards/` |
| 4. Response | done, `docs/stage4-predictions.md` |
| 5. Operate and survive | built, **not yet measured**: predictions are committed first (`docs/stage5-predictions.md`) |

## Quick start

    export LOCALSTACK_AUTH_TOKEN=<your token>
    source scripts/env.sh
    make reset          # LocalStack + all four accounts
    make gate           # fmt, validate, tflint, unit tests, Checkov, Conftest
    make score          # "N of M evaluable CIS controls passing"

Requirements: Docker, Terraform >= 1.7, AWS CLI v2, tflint, conftest, Python 3.10+.

## Stage 5: operate and survive

    make ops-test                      # watchdog, SLOs, restore drill, chaos logic, runbooks (no LocalStack)
    make ops-probe WAIT=150            # which operations features does this LocalStack really implement?
    make ops-up                        # detector + responder with checkpoint, resume and heartbeats
    make ops-watchdog PUBLISH=1        # probe, restart (with a budget), publish ComponentUp to CloudWatch
    make stage5-run LABEL=stage5-v1-baseline NORESUME=1   # break things on purpose, WITHOUT the fixes
    make stage5-run LABEL=stage5-v1                       # the same, WITH checkpoint and resume
    make ops-drill                     # backup and restore drill, prints the RTO
    WRITE=1 make ops-slo               # three SLOs and their error budgets

Backup and patching are Terraform toggles (`-var enable_backup=true -var enable_patching=true` on the workload root), off until the probe says LocalStack supports them (ADR-0017).

## Docs

* `docs/STAGE1.md`: the full build guide
* `docs/adr/0017-*.md`, `docs/adr/0018-*.md`, `docs/slo.md`, `docs/ops-contract.md`, `docs/runbooks/`
* `docs/cis-mapping.md`, `docs/threat-model.md`, `docs/adr/`, `docs/localstack-limitations.md`