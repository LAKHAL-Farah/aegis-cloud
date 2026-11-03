# CloudPurple scorecard: stage3-v5-wazuh

_Generated 2026-11-03 21:12 UTC_

**Detected: 8 of 12  |  Prevented on hardened twin: 3 of 12  |  Neither: 3  |  Errored: 0**

Mean time to detect: 3.1 s

Other alerts raised on purple during the run (not credited to a scenario): 2 (W-100151 x1, W-100160 x1)

| ID | ATT&CK | Scenario | Purple (vulnerable) | Hardened | Telemetry | Detected | MTTD | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S01 | T1580 | Cloud infrastructure discovery | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S02 | T1530 | S3 data exfiltration | SUCCEEDED | SUCCEEDED | DATA-EVENT (lookup-events cannot see it; check the trail's S3 destination manually) | no | - | NEITHER |
| S03 | T1136.003 | Backdoor IAM user + access key | SUCCEEDED | DENIED (IAM (boundary or policy)) | FULL | yes | 4.6 s | PREVENTED+DETECTED |
| S04 | T1562.008 | Disable CloudTrail logging | SUCCEEDED | DENIED (SCP) | NONE | no | - | PREVENTED |
| S05 | T1562.007 | Open a security group to the world | SUCCEEDED | SUCCEEDED | FULL | yes | 3.6 s | DETECTED |
| S06 | T1537 | Backdoor bucket policy | SUCCEEDED | SUCCEEDED | FULL | yes | 2.4 s | DETECTED |
| S07 | T1530 | Make the data bucket public | SUCCEEDED | SUCCEEDED | FULL | yes | 2.2 s | DETECTED |
| S08 | T1078.004 | Use a leaked access key | SUCCEEDED | SUCCEEDED | FULL | no | - | NEITHER |
| S09 | T1098 | Privilege escalation via policy versions | SUCCEEDED | DENIED (IAM (boundary or policy)) | FULL | yes | 1.7 s | PREVENTED+DETECTED |
| S10 | T1485 | Schedule KMS key deletion | SUCCEEDED | SUCCEEDED | FULL | yes | 1.5 s | DETECTED |
| S11 | T1555.006 | Harvest secrets | SUCCEEDED | SUCCEEDED | FULL | yes | 2.3 s | DETECTED |
| S12 | T1490 | Suspend versioning and delete objects | SUCCEEDED | SUCCEEDED | FULL | yes | 6.1 s | DETECTED |

## Notes

* S03 hardened: DENIED: User: arn:aws:iam::844227338124:user/dev-svc is not authorized to perform: iam:CreateUser on resource: arn:aws:iam::844227338124:user/backdoor-37fd9d72-S03 because no identity-based policy allows the 
* S03 matched alert: AegisCloud: IAM user created (denied attempts alert too)
* S04 hardened: DENIED: User: arn:aws:iam::844227338124:user/dev-svc is not authorized to perform: cloudtrail:StopLogging on resource: arn:aws:cloudtrail:us-east-1:844227338124:trail/hardened-trail with an explicit deny in a
* S05 matched alert: AegisCloud: security group ingress opened to the internet
* S06 matched alert: AegisCloud: bucket policy changed
* S07 matched alert: AegisCloud: bucket ACL grants public access
* S09 hardened: DENIED: User: arn:aws:iam::844227338124:user/intern is not authorized to perform: iam:CreatePolicyVersion on resource: arn:aws:iam::844227338124:policy/intern-policy because no identity-based policy allows th
* S09 matched alert: AegisCloud: IAM policy version created or changed
* S10 matched alert: AegisCloud: KMS key scheduled for deletion
* S11 matched alert: AegisCloud: secret value read
* S12 matched alert: AegisCloud: bucket versioning suspended
