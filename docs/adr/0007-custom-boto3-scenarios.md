# ADR-0007: Custom boto3 attack scenarios instead of Stratus Red Team

* Status: accepted
* Date: 2026-10-30

## Context
Stratus Red Team ships ready-made AWS techniques, but it is built for real AWS accounts, warms up its own infrastructure, and gives limited control over the endpoint, the acting identity and cleanup. We need to run the same attack against a vulnerable and a hardened account and to restore state between runs.

## Decision
Each scenario is a small Python function with explicit ATT&CK ID, expected CloudTrail events, expected detection, and an idempotent cleanup. The acting identity is the stolen `dev-svc` key, or the account root with `--as-root` to isolate SCP effects.

## Consequences
* (+) Full control, deterministic, runs entirely on LocalStack, easy to extend and unit-test.
* (-) We maintain the techniques ourselves. Stratus techniques can be added later as an optional cross-check on real AWS.