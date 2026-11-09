# Triage inside a real approval (live on LocalStack), 2026-11-08

Console output of `make respond-prompt`, pasted by the repository owner. The responder ran with `--approver file --advisor triage`; the
attack was S11 (harvest a secret) on the weak twin. Wording by the deterministic template (no model).

```
MEDIUM: Secret read by an unexpected identity: purple/db-password
  - Deactivate access key ...ZK2R of IAM user dev-svc
  - Create a replacement key and store it in Secrets Manager as aegis/rotated-access-key/555555555555/dev-svc
  - [triage, advisory only, words by template] P3: AEG-CRED-001 (T1555.006, Credential Access) for dev-svc in account 555555555555. Reasons: severity medium; the principal is admin, or one step from it, according to the IAM scan.
  - [triage] proposal: the playbook `leaked_key` is what the plan above does; you still decide
  - [triage] evidence: related findings: 0; IAM exposure: admin; playbook match: leaked_key
  - [triage] check next: find out who else read the secret and rotate it if the reader is not expected
Approve be845437237c? [y/N] y
approved
```

What followed in the audit trail (`make respond-audit`), excerpt: approval by `donutello` after 23.452 s; key deactivated; a first `rotate`
failed with `LimitExceeded`; a second `deactivate` and a second `rotate` succeeded; `verify` appears twice with sequence 25; two outcomes
(`contained`, then `partial`); `CHAIN BROKEN: chain broken at seq 25`. Cause and fix: ADR-0023. The broken audit file is kept as evidence and not repaired.

## Second attempt: nobody answered (silence is a denial)

Same attack, new incident `7b26047212a1`, after the single-responder fix (ADR-0023). The approval prompt was not answered within the
120 s limit. Audit trail excerpt:

```
1 received   ok
2 plan       ok
3 advice     ok       {"lines": ["[triage, advisory only, words by template] P3: AEG-CRED-001 ..."]}
4 approval   denied   {"automated": false, "by": "timeout", "reason": "no decision within 120 s", "waited_s": 120.188}
5 outcome    timeout  {"detail": "no decision within 120 s"}
chain OK: 5 records, chain intact
```

`aws iam list-access-keys --user-name dev-svc` afterwards still showed the original key, Active. One incident produced one record of each
step, and the chain verified: the duplicate-responder fault did not recur. This is the live confirmation of "silence is a denial".
