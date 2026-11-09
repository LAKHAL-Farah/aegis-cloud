# AegisCloud

A Terraform-built, CIS-mapped AWS landing zone that is **attacked on purpose, detects the attack, and responds with human approval**,
with every detection mapped to MITRE ATT&CK. It runs on LocalStack for AWS, so it costs nothing and nothing here has touched a real
AWS account (see `docs/real-aws.md`).

> Portfolio and learning project. Simulated behaviour is labelled as simulated. Read "What this does not show" before quoting a number.

## Results

Every number below is computed from the evidence files named in `docs/evidence/headline.json` (`make portfolio`), and `make docs-check`
fails if this table disagrees with them (ADR-0022).

| | Result | Evidence |
| --- | --- | --- |
| Attacks run | <!--num:scenarios-->12<!--/num--> ATT&CK-mapped scenarios on a weak twin and a hardened twin | `docs/evidence/scorecards/` |
| Detected before any detection existed | <!--num:baseline_detected-->0<!--/num--> of <!--num:scenarios-->12<!--/num--> (<!--num:baseline_prevented-->3<!--/num--> were blocked by controls) | `baseline.md` |
| Detected after Stage 3 | <!--num:detected-->11<!--/num--> of <!--num:scenarios-->12<!--/num--> (<!--num:detected_pct_of_all-->91.7<!--/num-->%), which is <!--num:detected_scorable-->11<!--/num--> of <!--num:scorable-->11<!--/num--> scorable: <!--num:excluded-->S08<!--/num--> cannot be observed on LocalStack (ADR-0014) | `stage3-v8.md` |
| Mean time to detect | <!--num:mttd_mean_s-->3.5<!--/num--> s | `stage3-v8.md` |
| Contained by an approval-gated playbook | <!--num:response_contained-->2<!--/num--> of <!--num:response_pairs-->2<!--/num--> scenarios, mean <!--num:a2c_mean_s-->12.3<!--/num--> s from attack (worst <!--num:a2c_worst_s-->14.5<!--/num--> s), machine time <!--num:machine_mean_s-->0.21<!--/num--> s. **The approval was <!--num:response_approval-->simulated<!--/num--> in this run** | `stage4-v7.md` |
| Chaos: kill the detector or the responder mid-incident | without the fixes <!--num:chaos_baseline_lost-->2<!--/num--> of <!--num:chaos_experiments-->2<!--/num--> events lost; with checkpoint and resume <!--num:chaos_survived-->2<!--/num--> of <!--num:chaos_experiments-->2<!--/num--> survived | `docs/evidence/chaos/` |
| Backup and restore drill | <!--num:drill_verified-->6<!--/num--> of <!--num:drill_objects-->6<!--/num--> objects restored and verified, RTO <!--num:drill_rto_s-->3.4<!--/num--> s | `restore-drill.json` |
| SLOs | <!--num:slo_ok-->1<!--/num--> of <!--num:slo_total-->3<!--/num--> OK on <!--num:slo_detection_events-->2<!--/num--> events, <!--num:slo_no_data-->2<!--/num--> have no data in the window | `slo/latest.md` |
| IAM Sentinel on LocalStack (live, first run) | <!--num:sentinel_live_accounts-->6<!--/num--> accounts scanned, <!--num:sentinel_live_unresolved-->0<!--/num--> unresolved policies; weak twin: <!--num:sentinel_live_purple_escalates-->1<!--/num--> escalation path and <!--num:sentinel_live_purple_admin-->1<!--/num--> standing admin; hardened twin: <!--num:sentinel_live_hardened_escalates-->0<!--/num--> and <!--num:sentinel_live_hardened_admin-->0<!--/num-->; <!--num:sentinel_live_other_unexpected_admin-->0<!--/num--> unexpected admins elsewhere | `sentinel-live.md` |
| IAM Sentinel on the twins (moto, offline) | weak twin: <!--num:sentinel_purple_escalates-->1<!--/num--> escalation path and <!--num:sentinel_purple_admin-->1<!--/num--> standing admin; hardened twin: <!--num:sentinel_hardened_escalates-->0<!--/num--> and <!--num:sentinel_hardened_admin-->0<!--/num--> | `sentinel-offline.md` |
| Triage evaluation (offline, no model) | passes: <!--num:triage_pass-->yes<!--/num-->; median <!--num:triage_median_ms-->1.9<!--/num--> ms | `triage-eval.md` |

## What this does not show

* **Nothing has run on real AWS.** The live Terraform roots hard-code LocalStack endpoints and test credentials, and the
  `managed-security` module that ADR-0004 describes does not exist. See `docs/real-aws.md`.
* **The measured approval was simulated.** A run with a person at a terminal also exists (`docs/stage4-predictions.md`). No approval
  has been measured through Slack itself.
* **S08 is excluded from the scored denominator** because the emulator does not record the caller's client. It is still run and still shown.
* **Falco has rules and a bridge, not a measured detection.** No scenario exercises a container (ADR-0011).
* **Stage 6 is only partly live.** The IAM scan and the triage note inside a real approval have run on LocalStack (template wording, file
  approver). Least privilege from a real trail, any live model run, and the n8n hand-off are not recorded yet (`docs/stage6-predictions.md`).
* **The Stage 4 and 5 headline runs are small**: two playbook scenarios and two chaos experiments. They show the mechanism works, not a rate.
* **The release signing path has been tested with a local key** (build, sign, verify, tamper check and reproducible rebuild on the owner's machine,
  `docs/evidence/release-local.md`); the keyless GitHub Actions path runs on the first tag.

## Status

| Stage | State |
| --- | --- |
| 1. SecureLanding | in progress: modules, CI gates and `make score` exist; `docs/cis-mapping.md` |
| 2. CloudPurple attack range | done, scorecards in `docs/evidence/scorecards/` |
| 3. Detection | done, scorecards in `docs/evidence/scorecards/` |
| 4. Response | done, `docs/stage4-predictions.md` |
| 5. Operate and survive | measured on LocalStack (chaos, restore drill, SLOs), `docs/stage5-predictions.md` |
| 6. Intelligence | built; IAM scan run live once, the rest tested offline: `docs/stage6-predictions.md` |
| 7. Polish | architecture, threat model, lessons learned, ADRs, signed releases and SBOM, generated numbers: this page and `docs/` |

## Architecture

See `docs/architecture.md` for diagrams. In one line: Terraform builds the accounts, a range attacks them, a Python engine turns
CloudTrail into ASFF findings (with Wazuh and OpenSearch alongside), a responder asks a person before it contains anything, a
watchdog and checkpoint keep the pipeline alive, and IAM Sentinel and a triage note advise without deciding.

## Quick start

    export LOCALSTACK_AUTH_TOKEN=<your token>
    source scripts/env.sh
    make reset          # LocalStack + all four accounts
    make gate           # fmt, validate, tflint, unit tests, Checkov, Conftest
    make score          # "N of M evaluable CIS controls passing"

Requirements: Docker, Terraform >= 1.7, AWS CLI v2, tflint, conftest, Python 3.10+.

## Stage 5: operate and survive

    make ops-test                      # watchdog, SLOs, restore drill, chaos logic, runbooks (no LocalStack)
    make ops-probe WAIT=150            # which operations features does this LocalStack really implement?
    make ops-up                        # detector + responder with checkpoint, resume and heartbeats
    make ops-watchdog PUBLISH=1        # probe, restart (with a budget), publish ComponentUp to CloudWatch
    make stage5-run LABEL=stage5-v1-baseline NORESUME=1   # break things on purpose, WITHOUT the fixes
    make stage5-run LABEL=stage5-v1                       # the same, WITH checkpoint and resume
    make ops-drill                     # backup and restore drill, prints the RTO
    WRITE=1 make ops-slo               # three SLOs and their error budgets

Backup and patching are Terraform toggles (`-var enable_backup=true -var enable_patching=true` on the workload root), off until the probe says LocalStack supports them (ADR-0017).

## Stage 6: intelligence

    make intel-test                    # Sentinel, triage and the responder hook (moto, no LocalStack, no network)
    make sentinel-scan                 # needs LocalStack and the range: snapshots every account, finds escalation paths
    make sentinel-leastpriv ACCT=<id> PRINCIPAL=<name>   # a least-privilege policy from observed CloudTrail, with its checks
    make triage-eval WRITE=1           # offline evaluation of the triage note
    python3 sentinel/tools/offline_eval.py --write       # both twins through moto, no LocalStack

IAM Sentinel only reads IAM. The triage note is shown to the approver after the plan and cannot change what runs (ADR-0019, ADR-0020).
Turn it on in the responder with `--advisor triage` (`make respond-up ADVISOR=triage`). Only one executing responder may run per state
directory (ADR-0023): start it once, and use `make respond-down` before starting it again.

## Stage 7: ship it

    make release-all                   # reproducible Lambda zip, SBOM, sign, verify (set COSIGN_KEY and COSIGN_PUBKEY for a local key)
    make sbom-validate                 # SBOM against the official CycloneDX 1.5 schema (needs network)
    make portfolio                     # recompute the headline numbers and the CV line from the evidence
    make docs-check                    # README numbers, architecture paths and ADR numbering against the repo
    make secrets-scan                  # gitleaks over the history

Pushing a tag like `v1.0.0` runs `.github/workflows/release.yml`: keyless signing, verification, then the files are attached to the
release. How to verify a release is in `docs/RELEASE.md`. A 90-second demo script is in `docs/demo-script.md`; the video itself is not
recorded yet.

## Docs

* `docs/architecture.md`, `docs/threat-model.md`, `docs/lessons-learned.md`, `docs/real-aws.md`
* `docs/adr/`: decisions 0001 to 0023
* `docs/stage*-predictions.md`: predictions committed before the measurement, with the misses kept
* `docs/intel-contract.md`, `docs/slo.md`, `docs/ops-contract.md`, `docs/detection-contract.md`, `docs/runbooks/`
* `docs/cis-mapping.md`, `docs/localstack-limitations.md`

## License and use

LocalStack's student tier is non-commercial. This repository is a learning project.
