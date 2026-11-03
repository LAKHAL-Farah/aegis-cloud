# CloudPurple scorecard: stage3-v5-python

_Generated 2026-11-03 21:12 UTC_

**Detected: 11 of 12  |  Prevented on hardened twin: 3 of 12  |  Neither: 1  |  Errored: 0**

Mean time to detect: 2.7 s

Other alerts raised on purple during the run (not credited to a scenario): 1 (AEG-IMPACT-003 x1)

| ID | ATT&CK | Scenario | Purple (vulnerable) | Hardened | Telemetry | Detected | MTTD | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | T1580 | Cloud infrastructure discovery | SUCCEEDED | SUCCEEDED | FULL | yes | 13.4 s | DETECTED |
| S02 | T1530 | S3 data exfiltration | SUCCEEDED | SUCCEEDED | DATA-EVENT (lookup-events cannot see it; check the trail's S3 destination manually) | yes | 2.8 s | DETECTED |
| S03 | T1136.003 | Backdoor IAM user + access key | SUCCEEDED | DENIED (IAM (boundary or policy)) | FULL | yes | 2.4 s | PREVENTED+DETECTED |
| S04 | T1562.008 | Disable CloudTrail logging | SUCCEEDED | DENIED (SCP) | NONE | yes | 1.9 s | PREVENTED+DETECTED |
| S05 | T1562.007 | Open a security group to the world | SUCCEEDED | SUCCEEDED | FULL | yes | 1.7 s | DETECTED |
| S06 | T1537 | Backdoor bucket policy | SUCCEEDED | SUCCEEDED | FULL | yes | 1.5 s | DETECTED |
| S07 | T1530 | Make the data bucket public | SUCCEEDED | SUCCEEDED | FULL | yes | 1.4 s | DETECTED |
| S08 | T1078.004 | Use a leaked access key | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S09 | T1098 | Privilege escalation via policy versions | SUCCEEDED | DENIED (IAM (boundary or policy)) | FULL | yes | 0.8 s | PREVENTED+DETECTED |
| S10 | T1485 | Schedule KMS key deletion | SUCCEEDED | SUCCEEDED | FULL | yes | 0.6 s | DETECTED |
| S11 | T1555.006 | Harvest secrets | SUCCEEDED | SUCCEEDED | FULL | yes | 0.4 s | DETECTED |
| S12 | T1490 | Suspend versioning and delete objects | SUCCEEDED | SUCCEEDED | FULL | yes | 3.4 s | DETECTED |

## Notes

* S01 matched alert: Cloud infrastructure discovery burst: 4 calls across 3 services (DescribeSecurityGroups by dev-svc)
* S02 matched alert: Bulk S3 object download: 10 objects from purple-data-555555555555 (GetObject by dev-svc)
* S03 hardened: DENIED: User: arn:aws:iam::844227338124:user/dev-svc is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::844227338124:user/backdoor-37fd9d72-S03 because no identity-based policy allows the 
* S03 matched alert: IAM user created: backdoor-37fd9d72-S03 (CreateUser by dev-svc)
* S04 hardened: DENIED: User: arn:aws:iam::844227338124:user/dev-svc is not authorized to perform: cloudtrail:StopLogging on resource: arn:aws:cloudtrail:us-east-1:844227338124:trail/hardened-trail with an explicit deny in a
* S04 matched alert: Trail observed not logging: purple-trail (TrailStateObserved by aegis-detector)
* S05 matched alert: Security group opened to the internet: sg-b4cc480749875437f (AuthorizeSecurityGroupIngress by dev-svc)
* S06 matched alert: Bucket policy changed, body not recorded so the principal cannot be checked: purple-data-555555555555 (PutBucketPolicy by dev-svc)
* S07 matched alert: Bucket exposed to the public: purple-data-555555555555 (Block Public Access relaxed) (PutPublicAccessBlock by dev-svc)
* S09 hardened: DENIED: User: arn:aws:iam::844227338124:user/intern is not authorized to perform: iam:CreatePolicyVersion on resource: arn:aws:iam::844227338124:policy/intern-policy because no identity-based policy allows th
* S09 matched alert: IAM policy rewritten by a non-administrator: intern-policy (CreatePolicyVersion by intern)
* S10 matched alert: KMS key scheduled for deletion: 5a583dba-edfa-458d-9b0e-6c46023729c5 (ScheduleKeyDeletion by dev-svc)
* S11 matched alert: Secret read by an unexpected identity: purple/db-password (GetSecretValue by dev-svc)
* S12 matched alert: Bucket versioning suspended: purple-data-555555555555 (PutBucketVersioning by dev-svc)
