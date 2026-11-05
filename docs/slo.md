# Service level objectives

Three SLOs, defined in `ops/slo.json` (data, not code), computed by `make ops-slo` from what the pipeline already writes
(ADR-0017). `WRITE=1 make ops-slo` saves `docs/evidence/slo/latest.md|json`.

| SLO | SLI (a good event is...) | Target | Why this number |
| --- | --- | --- | --- |
| Detection path is up | a watchdog tick where LocalStack and the detector were both up | 99% | an attack during an outage is only seen if the detector resumes (ADR-0018); 99% of 24 h is 14 minutes |
| Findings within 30 s of the event | a finding whose `CreatedAt` is within 30 s of the CloudTrail event time | 95% | Stage 3 measured 0.4 to 14 s, dominated by log delivery |
| Containment machine time within 5 s | a CONTAINED incident whose machine time (detected to contained, approval wait excluded) is at most 5 s | 95% | Stage 4 measured 0.2 to 0.3 s |

## How to read the report
* **Error budget left** = 1 minus (bad events / bad events the target allows). 100% = untouched, 0% = spent exactly, "overspent" = breached.
* **Status** `OK`, `AT RISK` (under 25% of the budget left), `BREACHED` (SLI under target), `NO DATA` (no events in the window).
* With fewer than 20 events the report says so: a 95% target on 3 events is not evidence. A lab run produces a handful of
  events, so expect that note until the stack runs unattended for a day or more.

## What counts, and what deliberately does not
* **Human decisions are not failures.** DENIED, TIMEOUT, REFUSED and NOOP incidents are people or policy deciding, so they are excluded from the response SLO. PARTIAL and FAILED are failures.
* **Approval wait is excluded** from the response SLO. The 90-second end-to-end goal (attack to contained) depends on a person's thumb; it is a demo target (Stage 4), not an SLO.
* **A watchdog that was not running says nothing.** Gaps in `health.jsonl` are not counted as up or down; the availability SLI only uses ticks that exist. Run the watchdog under the supervised stack or the number is meaningless.

## What this is not
It is not CloudWatch's view of the system. CloudWatch gets the heartbeat metric and the CIS alarms for portability to real
AWS (see `terraform/modules/monitoring`); LocalStack does not evaluate alarms (`docs/evidence/ops-probe.md`), so the numbers above are computed by us.
