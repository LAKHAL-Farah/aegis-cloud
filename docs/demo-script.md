# 90-second demo script

Goal: show the loop in one take: attack, alert, approval, fixed, proof. The video is **not recorded yet**; this is the plan.
Every command below exists (`make docs-test` checks the `make` targets). Nothing is faked on screen except where it says so.

## Before recording (not in the 90 seconds)

    export LOCALSTACK_AUTH_TOKEN=<token>; source scripts/env.sh
    make reset               # clean accounts
    make range-up            # weak and hardened twins
    make siem-up && make siem-setup   # OpenSearch Dashboards on http://localhost:5601
    make detect-up           # detector running
    make respond-up APPROVER=slack ADVISOR=triage   # or APPROVER=file and use `make respond-prompt` in a second terminal

Use a Slack channel and an allow-listed approver id if recording the Slack version; otherwise use the terminal approver. Say which
one is on screen. The measured numbers in the README used a simulated approver, so do not quote them over the video.

## Take

| Time | On screen | Say |
| --- | --- | --- |
| 0:00 | Terminal and Dashboards side by side | "This AWS account is deliberately weak, and nothing is watching it yet. Everything here runs on LocalStack." |
| 0:08 | `make attack LABEL=demo ARGS="--only S11"` | "I harvest a secret the way an attacker with a stolen key would." |
| 0:20 | Detector log or Dashboards: the alert for the secret read appears | "The detector turns CloudTrail into a finding mapped to ATT&CK T1555.006." |
| 0:30 | Slack (or terminal) shows the plan and, if `--advisor triage` is on, the advisory lines after it | "Nothing changes until a person approves. The note under the plan is advisory: it cannot change what runs." |
| 0:45 | Approve | "I approve." |
| 0:50 | Responder log line: contained and verified | "The key is deactivated, not deleted, and the responder checks that it really is inactive." |
| 1:05 | `make respond-audit` | "Every step is on a hash-chained audit trail." |
| 1:15 | `docs/evidence/portfolio-numbers.md` or the README results table | "Across 12 attacks: 0 detected before, 11 of 12 after, 11 of 11 scorable. The one excluded cannot be observed on this emulator. The approval in these numbers was simulated." |
| 1:25 | End card with the repository name | |

## Rules for the recording

* Cut nothing that makes the run look faster than it was. If a step takes 10 seconds, show 10 seconds or speed it up visibly.
* Say "simulated" or "LocalStack" wherever it applies. The README's "What this does not show" list is the script's last paragraph.
* If the attack is detected slower than expected, that is the demo: log delivery was the slow leg in every measured run.
