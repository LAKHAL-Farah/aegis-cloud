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
## Amendment (2026-11-06, Stage 7)
The status line above says the module was built in Stage 3. On the `stage5/operate` branch it is not there: a search of the
repository (modules, live roots, variables, docs) finds `managed-security` and `enable_managed_security` only in this ADR. The
decision still stands as intent. The consequence "the same Terraform targets real AWS by changing provider endpoints and one flag"
is **not demonstrated**: the live roots hard-code LocalStack endpoints and test credentials (see `docs/real-aws.md`).
