# AegisCloud

Terraform-built, CIS-mapped AWS landing zone that gets attacked on purpose, detects the attack, and responds automatically. Runs on LocalStack for AWS; the same Terraform targets real AWS by changing the provider endpoints (see ADR-0004).

> Portfolio / learning project. Simulated behaviour is labelled as simulated; see `docs/localstack-limitations.md`.

## Status

| Stage | State |
| --- | --- |
| 1. SecureLanding | in progress, see `docs/STAGE1.md` |
| 2. CloudPurple attack range | planned |
| 3. Detection | planned |
| 4. Response | planned |

## Quick start

    export LOCALSTACK_AUTH_TOKEN=<your token>
    source scripts/env.sh
    make reset          # LocalStack + all four accounts
    make gate           # fmt, validate, tflint, unit tests, Checkov, Conftest
    make score          # "N of M evaluable CIS controls passing"

Requirements: Docker, Terraform >= 1.7, AWS CLI v2, tflint, conftest, Python 3.10+.

## Docs

* `docs/STAGE1.md`: the full build guide
* `docs/cis-mapping.md`, `docs/threat-model.md`, `docs/adr/`, `docs/localstack-limitations.md`