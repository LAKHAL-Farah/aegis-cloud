# ADR-0014: Scorable denominator and documented exclusions

* Status: accepted
* Date: 2026-11-03

## Context
S08 (a leaked key used from a new client) cannot be detected on LocalStack. The telemetry probe
(`docs/evidence/telemetry-probe.md`) shows CloudTrail records `userAgent: console.amazonaws.com` and
`sourceIPAddress: 1.2.3.4` for every caller, so the signal the scenario describes never reaches the log.
Counting S08 as a miss says something about the lab, not about the detections.

## Decision
* A scenario listed in `docs/known-limits.json` still runs, still appears in every table and still keeps its
  raw result. It leaves the **scorable** denominator: `11 of 11 scorable (12 run, S08 excluded)`.
* The exclusion is never silent. `headline()`, the scorecard markdown, the ATT&CK matrix and its HTML all print
  the run count and the excluded IDs. A bare `11/11` is not produced anywhere.
* An entry must cite a file under `docs/evidence/` that shows the limitation (`test_scorable.py` enforces it).
* Saved scorecards are evidence and are not edited. The scorable count is computed from their rows at report time.
* No rule was added or changed to make S08 pass. `test_not_rigged.py` (ADR-0013) still applies.

## Consequences
* (+) The headline measures the detections, and the lab limit stays visible next to it.
* (-) The baseline's "0 of 12" reads "0 of 11" in the matrix. The saved baseline card still says 12.
* (-) Whoever reads only the headline sees `11 of 11`. The post must carry the S08 sentence and not shorten it.
* S08 is detectable on real AWS. Re-include it (delete the entry) once a run against real CloudTrail records it.
