# ATT&CK coverage: baseline to stage3-v5

| | baseline | stage3-v5 |
| --- | --- | --- |
| Detected | 0 of 12 | **11 of 12** |
| Prevented on hardened twin | 3 of 12 | 3 of 12 |
| Mean time to detect | - | 2.7 s |
| Other alerts during the run | - | 11 |

## Per scenario

| ID | ATT&CK | Scenario | Before | After | MTTD | Detected by | Why missed |
| --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | T1580 | Cloud infrastructure discovery | missed | **detected** | 13.4 s | AEG-DISC-001 (python-engine) | - |
| S02 | T1530 | S3 data exfiltration | missed | **detected** | 2.8 s | AEG-EXFIL-003 (python-engine) | - |
| S03 | T1136.003 | Backdoor IAM user + access key | missed | **detected** | 2.4 s | AEG-PERS-001 (python-engine) | - |
| S04 | T1562.008 | Disable CloudTrail logging | missed | **detected** | 1.9 s | AEG-EVAS-002 (python-engine) | - |
| S05 | T1562.007 | Open a security group to the world | missed | **detected** | 1.7 s | AEG-EVAS-003 (python-engine) | - |
| S06 | T1537 | Backdoor bucket policy | missed | **detected** | 1.5 s | AEG-EXFIL-001 (python-engine) | - |
| S07 | T1530 | Make the data bucket public | missed | **detected** | 1.4 s | AEG-EXFIL-002 (python-engine) | - |
| S08 | T1078.004 | Use a leaked access key | missed | **MISSED** | - | - | known limitation: LocalStack records userAgent as console.amazonaws.com for every client, so a new-client signal never reaches CloudTrail (docs/evidence/telemetry-probe.md). Not detectable here; detectable on real AWS. |
| S09 | T1098 | Privilege escalation via policy versions | missed | **detected** | 0.8 s | AEG-PRIV-001 (python-engine) | - |
| S10 | T1485 | Schedule KMS key deletion | missed | **detected** | 0.6 s | AEG-IMPACT-001 (python-engine) | - |
| S11 | T1555.006 | Harvest secrets | missed | **detected** | 0.4 s | AEG-CRED-001 (python-engine) | - |
| S12 | T1490 | Suspend versioning and delete objects | missed | **detected** | 3.4 s | AEG-IMPACT-002 (python-engine) | - |

## Matrix (tactic x technique)

* **Initial Access**: T1078.004 MISS
* **Persistence**: T1136.003 OK
* **Privilege Escalation**: T1098 OK
* **Defense Evasion**: T1562.008 OK, T1562.007 OK
* **Credential Access**: T1555.006 OK
* **Discovery**: T1580 OK
* **Collection**: T1530 OK, T1530 OK
* **Exfiltration**: T1537 OK
* **Impact**: T1485 OK, T1490 OK
