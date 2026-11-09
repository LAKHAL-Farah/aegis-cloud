# Threat model (Stage 1 baseline)

Scope of this first table: the landing zone only. Attack scenarios were added in Stage 2. The second part of this page (Stage 7) covers the platform itself: the detector, the responder, the new Stage 6 components, and the way it is shipped.

| Asset | Threat | Control (this repo) | Residual risk |
| --- | --- | --- | --- |
| Audit logs | Attacker with workload admin deletes evidence | Logs in a separate account, KMS-encrypted, bucket policy trusts one trail ARN, SCP `protect-logging` | Enforcement of SCPs on LocalStack unverified (see limitations) |
| Cloud account | Backdoor IAM user / long-lived key | Permission boundary denies `iam:CreateUser`/`CreateAccessKey`; no IAM users by design | Stage 2 demonstrates the twin where this is allowed |
| Data bucket | Public exposure | BPA on, OPA/Checkov gates, SCP `deny-public-s3-acls` | Detection of exposure is Stage 3 |
| Workload network | Inbound admin access | No public IPs, NACL deny rules, SG with no ingress, SSM instead of SSH | Egress 443 is open (needed for endpoints/updates) |
| Infrastructure code | Insecure change merged | CI gates, branch protection | Admin bypass of branch protection; skipped Checkov checks (listed, justified) |
| Build pipeline | Secrets leaked | No secrets in CI for the main gates; tokens only in repo secrets | Stage 7 adds Gitleaks and signed artifacts (done: `.gitleaks.toml`, `.github/workflows/security.yml`, `release/`) |
# Threats to and from the platform itself (Stage 7)

The first table asks "what can an attacker do to the AWS account". This one asks what an attacker, or a mistake, can do to
the tools that watch and defend it. Each row says what was actually tested, because a control that was only written down is
not a control yet.

| Asset | Threat | Control | Tested how | Residual risk |
| --- | --- | --- | --- | --- |
| Detection coverage | Attacker uses a technique the detector cannot see | 14 rules mapped to ATT&CK, scorecard with a baseline of 0 detected, honest misses | `docs/evidence/scorecards/` (11 of 11 scorable detected; S08 excluded, ADR-0014) | S08 is not observable on LocalStack (user agent is not recorded), so its detection is unmeasured, not absent. Real AWS may differ in both directions |
| Detector availability | Detector is killed or stalls, the outage becomes a blind spot | Watchdog, heartbeats, checkpoint and resume (ADR-0017, ADR-0018) | Chaos run with and without resume: events lost without it, survived with it (`docs/evidence/chaos/`) | The outage itself is still unmonitored in real time; resume detects it afterwards, with a delay |
| Responder authority | A forged or replayed approval triggers containment | Silence is a denial; approver ids on an allow list; on the Lambda path an approval is an HMAC over finding id, approver and expiry | `response/tests` (unsigned event, expired approval, approval signed by someone else, approval reused for another incident, no key configured) | The HMAC key and the Slack token live in environment variables. A compromised responder host holds both |
| Responder as a weapon | Attacker makes the responder contain a legitimate identity (denial of service) | Protected identities are never touched; containment is reversible (keys are deactivated, not deleted); the human sees the exact plan | `response/tests`, ADR-0015 | An attacker can still flood the approver with real-looking incidents. Alert fatigue is not solved |
| Audit trail | Records are altered after the fact, or two writers interleave | Hash chain over every step, verified on read; one executing responder per state directory (ADR-0023) | `AuditLog.verify()` is tested against edits, deletions and reordering | On 2026-11-08 two responders at once broke the chain (ADR-0023): the log is safe only with one writer, which is now enforced. A hash chain is tamper-evident, not tamper-proof: someone who can rewrite the whole file can rewrite the whole chain. Shipping the head hash somewhere else is not implemented |
| Triage note (Stage 6) | Attacker-controlled text (principal name, bucket name, user agent) tries to steer the note or the human, or reaches a chat as a mention, link or fake prompt | Code, not a model, decides priority and action. Untrusted strings are sanitised before use; model text must pass a validator and is otherwise replaced by a template; the model has no tools; the module cannot import AWS or call a playbook (ADR-0020) | `triage/tests` (hostile names, 9 kinds of misbehaving model, static checks) and mutation checks on the sanitiser | Only a fake model was tested. A real model may produce misleading but well-formed wording. With the model on, sanitised finding facts leave the machine |
| IAM analysis (Stage 6) | Sentinel misses a path, or invents one | Evaluator covers identity policies, boundaries, explicit deny, trust policies; conditions are flagged, not evaluated | `sentinel/tests` including deliberate breakages of the evaluator (ADR-0019) | Not modelled: session policies, resource policies, most SCP behaviour, cross-account access. A path through a Condition may be a false positive; a missing feature can be a false negative |
| Least-privilege output | A generated policy bakes an attacker's behaviour into a permission, or breaks a workload by being too narrow | Sensitive calls are left out and listed; the tool writes a file and never applies it; coverage of observed calls is checked | `sentinel/tests/test_leastpriv.py` | A rarely used action not seen in the window is cut. A person reviews every policy |
| Lambda package | Package is altered between build and deploy | Reproducible zip, CycloneDX SBOM, cosign signature, SBOM attested to the zip's digest | ADR-0021; `release/tests` with real cosign: a changed zip, a changed SBOM, another key and a mismatched attestation all fail | The keyless GitHub OIDC path has not run yet (first tag will). Nothing yet checks the signature at deploy time. boto3 comes from the Lambda runtime and is not pinned |
| Build pipeline and dependencies | A malicious or compromised action or binary | cosign and gitleaks are downloaded at a pinned version, cosign also at a pinned sha256 | `.github/workflows/release.yml`, `security.yml` | Third-party actions are pinned by major tag, like the rest of the repo, not by commit. Pinning by commit is a follow-up |
| Secrets in the repo | A real credential is committed | gitleaks over the history in CI; allowlist only by exact fake value | gitleaks 8.30.1 run over the tree: no findings after allowlisting the repo's own fake test keys | Detects known patterns only |
| The emulator | A result is true on LocalStack and false on AWS | Every limit is written down (`docs/localstack-limitations.md`) and the claims say "on LocalStack" | `docs/real-aws.md` lists what has and has not been checked | Nothing in this repo has run on real AWS |

## Out of scope

Insiders with write access to the repository or to the signing identity, attacks on AWS itself, and anything that needs real
accounts, real traffic or real users. A threat model for production use would start from those.
