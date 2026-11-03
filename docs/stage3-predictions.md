# Stage 3 predictions (written BEFORE the first scored run)


| ID | Attack | ATT&CK | Rule(s) | Needs from LocalStack | Predicted: detected? | Predicted MTTD |
| --- | --- | --- | --- | --- | --- | --- |
| S01 | Cloud infrastructure discovery | T1580 | AEG-DISC-001 | management events + a stable principal | yes | poll interval + delivery |
| S02 | S3 data exfiltration | T1530 | AEG-EXFIL-003 | **S3 data events in log files** | only if the probe says data events are delivered | |
| S03 | Backdoor IAM user + key | T1136.003 | AEG-PERS-001 | management events | yes | |
| S04 | Stop CloudTrail logging | T1562.008 | AEG-EVAS-001, AEG-EVAS-002 | the event, or the state poller (trail off for longer than one poll) | yes via the poller even if the event is missing | |
| S05 | Open a security group to the world | T1562.007 | AEG-EVAS-003 | request parameters | yes | |
| S06 | Backdoor bucket policy | T1537 | AEG-EXFIL-001 | request parameters (policy document) | yes | |
| S07 | Make the data bucket public | T1530 | AEG-EXFIL-002 | request parameters | yes | |
| S08 | Leaked key, new client | T1078.004 | AEG-ACCESS-001 | **user agent + identity name** | only if the probe says user agent is recorded | |
| S09 | Privilege escalation via policy version | T1098 | AEG-PRIV-001 | identity name | yes | |
| S10 | Schedule KMS key deletion | T1485 | AEG-IMPACT-001 | management events | yes | |
| S11 | Harvest secrets | T1555.006 | AEG-CRED-001 | management events | yes | |
| S12 | Suspend versioning, delete objects | T1490 | AEG-IMPACT-002 (+ AEG-IMPACT-003 for T1485) | `PutBucketVersioning` event | yes | |

Overall prediction: ____ of 12 detected. Expected misses and why: ____

Other things I expect to see: alerts on my own `make range-up` (secret reads, user creation), and alerts raised by the
root-run cleanup steps. Those are false positives or duplicates and go in the "other alerts" line of the scorecard.