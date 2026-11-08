# IAM Sentinel on LocalStack (live), 2026-11-08

Console output of `make sentinel-scan`, run by the repository owner against the real range, kept here as evidence.
Structured copy: `sentinel-live.json`. It is the first live run, so it is also the answer to prediction 9 in `docs/stage6-predictions.md`.

| Account | Role | Users and roles | Policies | Unresolved | Escalate | Standing admin | Expected admin | Ordinary |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 111111111111 | management | 5 | 5 | 0 | 0 | 0 | 1 | 4 |
| 222222222222 | log-archive | 3 | 4 | 0 | 0 | 0 | 1 | 2 |
| 333333333333 | security | 3 | 4 | 0 | 0 | 0 | 1 | 2 |
| 444444444444 | workload | 6 | 6 | 0 | 0 | 0 | 1 | 5 |
| 555555555555 | range, weak twin | 2 | 1 | 0 | **1** | **1** | 0 | 0 |
| 379134115842 | range, hardened twin | 6 | 5 | 0 | 0 | 0 | 1 | 5 |

* Weak twin: `dev-svc` is admin; `intern` escalates in one step by `iam:CreatePolicyVersion` on `intern-policy` (ESC-01, T1098).
* Every other account: the only admin is `aegis-break-glass-admin`, which matches the expected-admin pattern.
* No attached policy was left unresolved in any account.

Not done in this run: `make sentinel-leastpriv ACCT=555555555555 PRINCIPAL=dev-svc` said "no usable events for dev-svc; seen: nobody". It
ran before any attack, so `dev-svc` had not acted yet. To be repeated after an attack.
