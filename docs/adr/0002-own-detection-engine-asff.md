# ADR-0002: Own detection engine emitting ASFF

* Status: accepted
* Date: 2026-10-28

## Context
The spike showed GuardDuty and Security Hub return 501 on the student/hobby LocalStack tier.

## Decision
Detections (Wazuh rules and Python detectors over CloudTrail) emit findings in the AWS Security Finding Format (ASFF), each mapped to a MITRE ATT&CK technique.

## Consequences
* (+) On real AWS the same findings can be imported into Security Hub unchanged.
* (+) Detections are versioned code with tests (Detection-as-Code).
* (-) More to build and maintain than enabling a managed service. Stage 3 owns this.