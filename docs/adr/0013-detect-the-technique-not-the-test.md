# ADR-0013: Detect the technique, not the test

* Status: accepted
* Date: 2026-10-31

## Context
A detector tuned to the attack harness would score 12 of 12 and prove nothing.

## Decision
Rules are written from each scenario's `expected_detection` text as behaviour. A unit test (`test_not_rigged.py`) fails the build if detection code or `policy.json` contains a scenario ID, a run ID, the runner's user agent, the test user agent, the foreign test account, the range's account IDs, or range resource names. Environment facts that are legitimate inventory (service-identity naming convention, who may edit IAM policies) live in `policy.json`. A coverage test fails if an attack technique has no rule.

## Consequences
* (+) The re-run of the unmodified range is meaningful evidence.
* (-) `AEG-ACCESS-001` is policy-based (a service identity used through an interactive client), not behavioural, because the range has no benign history to learn from. This is the weakest detection and is labelled as such.