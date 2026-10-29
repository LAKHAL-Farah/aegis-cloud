# ADR-0003: Compliance score computed by AegisCloud, not AWS Config

* Status: accepted
* Date: 2026-10-28

## Context
On LocalStack, Config stores rule definitions but does not evaluate them (`start_config_rules_evaluation` and `describe_compliance_by_config_rule` are not implemented).

## Decision
`scripts/compliance_score.py` merges three sources per CIS control: (1) Checkov and OPA results on the Terraform code (preventive), (2) boto3 checks against the deployed state (detective), (3) Config rule definitions (kept for portability only, never trusted for a result). Output: "N of M evaluable controls passing", plus an explicit count of controls that cannot be evaluated.

## Consequences
* (+) A real, honest number even where the emulator is incomplete.
* (-) Two implementations of each check (static + live) must be kept consistent; `policies/cis_controls.json` is the single mapping.