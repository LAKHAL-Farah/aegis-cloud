# CloudPurple scorecard: as-root

_Generated 2026-10-31 15:41 UTC_

**Detected: 0 of 12  |  Prevented on hardened twin: 2 of 12  |  Neither: 10  |  Errored: 0**

| ID | ATT&CK | Scenario | Purple (vulnerable) | Hardened | Telemetry | Detected | MTTD | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | T1580 | Cloud infrastructure discovery | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S02 | T1530 | S3 data exfiltration | SUCCEEDED | SUCCEEDED | DATA-EVENT (lookup-events cannot see it; check the trail's S3 destination manually) | no | - | NEITHER |
| S03 | T1136.003 | Backdoor IAM user + access key | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S04 | T1562.008 | Disable CloudTrail logging | SUCCEEDED | DENIED (SCP) | NONE | no | - | PREVENTED |
| S05 | T1562.007 | Open a security group to the world | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S06 | T1537 | Backdoor bucket policy | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S07 | T1530 | Make the data bucket public | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S08 | T1078.004 | Use a leaked access key | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S09 | T1098 | Privilege escalation via policy versions | SUCCEEDED | DENIED (IAM policy) | PARTIAL | no | - | PREVENTED |
| S10 | T1485 | Schedule KMS key deletion | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S11 | T1555.006 | Harvest secrets | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S12 | T1490 | Suspend versioning and delete objects | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |

## Notes

* S04 hardened: DENIED: User: arn:aws:iam::402528835445:root is not authorized to perform: cloudtrail:StopLogging on resource: arn:aws:cloudtrail:us-east-1:402528835445:trail/hardened-trail with an explicit deny in a service
* S09 hardened: DENIED: User: arn:aws:iam::402528835445:user/intern is not authorized to perform: iam:CreatePolicyVersion on resource: arn:aws:iam::402528835445:policy/intern-policy because no identity-based policy allows th
