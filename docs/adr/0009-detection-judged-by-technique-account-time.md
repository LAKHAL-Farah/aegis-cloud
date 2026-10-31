# ADR-0009: Detections are scored by technique, account and time window

* Status: accepted
* Date: 2026-10-30

## Context
If detectors were told which scenario ran, the score would be rigged. A real detector only knows what it saw.

## Decision
Detectors write alert files (see `docs/detection-contract.md`). An attack counts as detected only if an alert carries the scenario's ATT&CK technique ID, the target account ID, and a `detected_at` within a window (default 120 s) after the attack started. MTTD is `detected_at - attack_start`.

## Consequences
* (+) Fair, source-agnostic scoring: Wazuh, the Python engine and Falco all use the same contract.
* (-) Two scenarios sharing a technique and run within the window could cross-match. Scenarios run sequentially with cleanup between them, which keeps this rare; the scorecard prints the matched alert for review.