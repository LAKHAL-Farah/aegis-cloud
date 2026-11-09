# CloudPurple scorecard: slack-demo

_Generated 2026-11-09 00:45 UTC_

**Detected: 1 of 1  |  Prevented on hardened twin: 0 of 1  |  Neither: 0  |  Errored: 0**

Mean time to detect: 17.8 s

| ID | ATT&CK | Scenario | Purple (vulnerable) | Hardened | Telemetry | Detected | MTTD | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S11 | T1555.006 | Harvest secrets | SUCCEEDED | SUCCEEDED | FULL | yes | 17.8 s | DETECTED |

## Notes

* S11 matched alert: Secret read by an unexpected identity: purple/db-password (GetSecretValue by dev-svc)
