# Log filter pattern probe (2026-11-06 02:22 UTC)

Three CloudTrail-shaped events were sent through each pattern; `yes` means a metric datapoint appeared. Record `localstack --version` next to this file.

| Pattern shape | Matched? |
| --- | --- |
| simple, quoted value | **yes** |
| simple, unquoted value | no |
| two terms with ||, parenthesised | no |
| && with a nested || | no |
| REAL CIS 4.5 (CloudTrail changes) | no |
| REAL CIS 4.7 (CMK disable/delete) | no |
| REAL CIS 4.10 (security groups) | no |
