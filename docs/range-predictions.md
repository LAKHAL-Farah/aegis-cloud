# Predictions (written BEFORE the first run)

Edit the "my prediction" columns if you disagree, then commit this file before `make attack`.

| ID | Attack | ATT&CK | purple: succeeds? | hardened: prevented by | CloudTrail records it? | Detected today |
| --- | --- | --- | --- | --- | --- | --- |
| S01 | Cloud infrastructure discovery | T1580 | yes | not prevented | yes | no |
| S02 | S3 data exfiltration | T1530 | yes | not prevented | no (data events) | no |
| S03 | Backdoor IAM user + key | T1136.003 | yes | permission boundary (explicit deny) | yes | no |
| S04 | Stop CloudTrail logging | T1562.008 | yes | SCP protect-logging (and boundary) | yes | no |
| S05 | Open security group to 0.0.0.0/0 | T1562.007 | yes | not prevented | yes | no |
| S06 | Backdoor bucket policy (external account) | T1537 | yes | not prevented | yes | no |
| S07 | Make bucket public (BPA off + public ACL) | T1530 | yes | SCP deny-public-s3-acls | yes | no |
| S08 | Leaked key used from an attacker tool | T1078.004 | yes | not prevented | yes | no |
| S09 | Privilege escalation via CreatePolicyVersion | T1098 | yes | permission boundary (implicit deny) | yes | no |
| S10 | Schedule KMS key deletion | T1485 | yes | not prevented | yes | no |
| S11 | Harvest secrets | T1555.006 | yes | not prevented | yes | no |
| S12 | Suspend versioning, delete objects | T1490 | yes | not prevented | partly (data events) | no |

Open questions the run answers: does LocalStack enforce permission boundaries (S03, S09)? does it enforce the `s3:x-amz-acl` SCP condition (S07)? does it record read-only and data events in CloudTrail (S01, S02)?