# AegisCloud

Terraform-built AWS landing zone (CIS-mapped) that gets attacked on purpose, detects the attack, and responds automatically. Runs on LocalStack for AWS; the same Terraform targets real AWS by swapping the provider endpoints.

## Start here: the feasibility spike

```bash
export LOCALSTACK_AUTH_TOKEN=<your student/hobby token>
make up        # starts LocalStack
make spike     # applies 6 probes + runs 17 behaviour checks
cat spike/spike-report.md
```

Paste `spike-report.md` back into the chat. It decides what Stage 1 relies on LocalStack for and what you build yourself.

Requirements: Docker, Terraform >= 1.6, AWS CLI v2, curl.

## Stages
See `docs/STAGE1.md` for the Stage 1 plan and repo conventions.
