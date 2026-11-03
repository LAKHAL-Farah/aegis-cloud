.venv/bin/python detections/detect.py rules
| Rule | ATT&CK | Tactic | Severity | Title |
| --- | --- | --- | --- | --- |
| AEG-ACCESS-001 | T1078.004 | Initial Access | high | Service identity used from an interactive client |
| AEG-CRED-001 | T1555.006 | Credential Access | medium | Secret read by an unexpected identity |
| AEG-DISC-001 | T1580 | Discovery | medium | Cloud infrastructure discovery burst |
| AEG-EVAS-001 | T1562.008 | Defense Evasion | critical | CloudTrail logging disabled or weakened |
| AEG-EVAS-002 | T1562.008 | Defense Evasion | critical | Trail observed not logging |
| AEG-EVAS-003 | T1562.007 | Defense Evasion | high | Security group opened to the internet |
| AEG-EXFIL-001 | T1537 | Exfiltration | high | Bucket policy grants access outside the account |
| AEG-EXFIL-002 | T1530 | Collection | high | Bucket exposed to the public |
| AEG-EXFIL-003 | T1530 | Collection | high | Bulk S3 object download |
| AEG-IMPACT-001 | T1485 | Impact | critical | KMS key scheduled for deletion |
| AEG-IMPACT-002 | T1490 | Impact | high | Bucket versioning suspended |
| AEG-IMPACT-003 | T1485 | Impact | critical | Bulk S3 object deletion |
| AEG-PERS-001 | T1136.003 | Persistence | high | IAM user created |
| AEG-PRIV-001 | T1098 | Privilege Escalation | high | IAM policy rewritten by a non-administrator |
