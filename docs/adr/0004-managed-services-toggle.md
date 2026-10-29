# ADR-0004: Managed security services behind a toggle

* Status: accepted (module built in Stage 3)
* Date: 2026-10-28

## Context
GuardDuty and Security Hub are unsupported on LocalStack but are the right tools on real AWS.

## Decision
A `managed-security` module wraps them behind `enable_managed_security`: `false` on LocalStack, `true` on real AWS.

## Consequences
* (+) Demonstrates that the same Terraform targets real AWS by changing provider endpoints and one flag.
* (-) The `true` path cannot be exercised in this lab; it is documented, not demonstrated.