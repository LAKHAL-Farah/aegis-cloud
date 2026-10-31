# Threat model (Stage 1 baseline)

Scope: the landing zone only. Attack scenarios are added in Stage 2.

| Asset | Threat | Control (this repo) | Residual risk |
| --- | --- | --- | --- |
| Audit logs | Attacker with workload admin deletes evidence | Logs in a separate account, KMS-encrypted, bucket policy trusts one trail ARN, SCP `protect-logging` | Enforcement of SCPs on LocalStack unverified (see limitations) |
| Cloud account | Backdoor IAM user / long-lived key | Permission boundary denies `iam:CreateUser`/`CreateAccessKey`; no IAM users by design | Stage 2 demonstrates the twin where this is allowed |
| Data bucket | Public exposure | BPA on, OPA/Checkov gates, SCP `deny-public-s3-acls` | Detection of exposure is Stage 3 |
| Workload network | Inbound admin access | No public IPs, NACL deny rules, SG with no ingress, SSM instead of SSH | Egress 443 is open (needed for endpoints/updates) |
| Infrastructure code | Insecure change merged | CI gates, branch protection | Admin bypass of branch protection; skipped Checkov checks (listed, justified) |
| Build pipeline | Secrets leaked | No secrets in CI for the main gates; tokens only in repo secrets | Stage 7 adds Gitleaks and signed artifacts |