# ADR-0017: The operations layer is our own watchdog and SLO report, with CloudWatch and AWS Backup as portable definitions

* Status: accepted
* Date: 2026-11-05

## Context
Stage 5 asks for alarms, patching, backups with a restore test, a chaos experiment and SLOs. The spike (ADR-0003 style
finding) showed that LocalStack stores many of these without running them: Config evaluation is absent, and CloudWatch
alarm evaluation, CloudTrail delivery to CloudWatch Logs, SSM command execution and AWS Backup restores are all unverified
here (`make ops-probe` records which). A number computed by a feature that does nothing is not a number.

## Decision
1. **Health is a heartbeat file plus a watchdog we wrote** (`ops/aegis_ops`). It probes, records every tick, restarts
   with a budget (3 per 10 minutes, then it stops and says "gave-up"), and can publish `Aegis/Pipeline ComponentUp` to CloudWatch.
2. **SLOs are computed from our own data** (watchdog log, responder audit trail, ASFF findings), so they mean the same on
   LocalStack and on real AWS. CloudWatch alarms on the same metric are defined in Terraform for portability, with
   `treat_missing_data = breaching` so that a dead watchdog also alarms.
3. **CIS section 4 (4.1 to 4.15) is Terraform:** the trail delivers to a KMS-encrypted log group, 15 metric filters and 15
   alarms notify an encrypted SNS topic. It is proven by `terraform test` and a live "definitions exist" check. It is NOT
   claimed to fire on LocalStack; our own detectors cover the same event families there (ADR-0002).
4. **The restore proof is an S3 versioning drill** (`make ops-drill`): write, destroy both ways (delete and overwrite),
   restore the last good version, verify every byte, report the RTO. AWS Backup (vault, plan, selection) and SSM Patch
   Manager (baseline, patch group, window, task) are Terraform modules behind `enable_backup` / `enable_patching`,
   default off, to be enabled once the probe says the provider's calls succeed. They are definitions, not evidence.
5. **Every alarm names a runbook** and a test fails if the page is missing or lacks Symptom, Check, Fix, Verify.

## Consequences
* (+) Every number in the Stage 5 post is one we measured, with a note saying how.
* (+) The same watchdog works against real AWS: swap the HTTP probes' endpoints, publish to real CloudWatch.
* (-) We maintain a small supervisor that systemd or ECS would give for free. Accepted: the point is to show what it measures.
* (-) Patching and backup are not observed running. The limitations file says so, and the CV line must not claim restores from AWS Backup.
* (-) The cost dashboard in the original plan is not built: Infracost already comments on pull requests, and LocalStack bills nothing, so a dashboard would plot zeros.
