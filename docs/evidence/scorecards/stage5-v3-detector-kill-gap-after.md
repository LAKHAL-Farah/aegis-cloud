# CloudPurple scorecard: stage5-v3-detector-kill-gap-after

_Generated 2026-11-06 02:05 UTC_

**Detected: 1 of 1  |  Prevented on hardened twin: 0 of 1  |  Neither: 0  |  Errored: 0**

Mean time to detect: 64.2 s

| ID | ATT&CK | Scenario | Purple (vulnerable) | Hardened | Telemetry | Detected | MTTD | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | T1580 | Cloud infrastructure discovery | SUCCEEDED | SUCCEEDED | FULL | yes | 64.2 s | DETECTED |

## Notes

* S01 matched alert: Cloud infrastructure discovery burst: 4 calls across 3 services (DescribeSecurityGroups by dev-svc)
