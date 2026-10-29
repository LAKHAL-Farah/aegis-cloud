# ADR-0005: No Config-based auto-remediation

* Status: accepted
* Date: 2026-10-28

## Context
Config remediation depends on rule evaluation, which LocalStack does not provide (see ADR-0003).

## Decision
Remediation is triggered from AegisCloud's own detections via EventBridge to n8n/Lambda/SSM (Stage 4).

## Consequences
* (+) Works identically on LocalStack and real AWS; every response has an approval step and audit trail.
* (-) We re-implement what Config remediation gives for free on real AWS.