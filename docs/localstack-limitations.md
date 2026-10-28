# AegisCloud spike report

Generated: 2026-10-28T20:06:23Z  |  Endpoint: http://localhost:4566

| Probe | Result | Notes |
|---|---|---|
| apply:organizations | PASS |  |
| apply:logging | PASS |  |
| apply:config | PASS |  |
| apply:guardduty | FAIL | [33m│[0m [0mexceptional situations such as recovering from errors or mistakes, or when |
| apply:securityhub | FAIL | [33m│[0m [0mexceptional situations such as recovering from errors or mistakes, or when |
| apply:eventing | PASS |  |
| api:multi-account-sts | PASS |  |
| api:org-describe | PASS |  |
| api:scp-listed | PASS |  |
| api:trail-status | PASS |  |
| api:trail-lookup-events | PASS |  |
| api:trail-delivers-to-s3 | PASS |  |
| api:config-recording | PASS |  |
| api:config-rule | PASS |  |
| api:config-compliance | FAIL |  aws: [ERROR]: An error occurred (InternalFailure) when calling the GetComplianceSummaryByConfigRule operation |
| api:guardduty-detector | EMPTY | call worked but output did not match /^[a-z0-9]{10,}/ (stub?) |
| api:securityhub-hub | FAIL |  aws: [ERROR]: An error occurred (InternalFailure) when calling the DescribeHub operation: Sorry, the security |
| api:securityhub-standards | FAIL |  aws: [ERROR]: An error occurred (InternalFailure) when calling the GetEnabledStandards operation: Sorry, the  |
| api:securityhub-findings | FAIL |  aws: [ERROR]: An error occurred (InternalFailure) when calling the GetFindings operation: Sorry, the security |
| api:eventbridge-to-sqs | PASS |  |

## How to read this
- **PASS** on apply AND behaviour: rely on LocalStack for this service.
- **PASS** on apply but **EMPTY/FAIL** on behaviour: the resource is a stub. Build your own logic (Wazuh rules, Lambda checks) and document it as a LocalStack limitation.
- **FAIL** on apply: check spike/logs/<name>.log. Often a provider argument issue, not a missing service.
- SCP enforcement is NOT tested here: the management account is exempt in real AWS. Stage 1 tests it with a member account.
