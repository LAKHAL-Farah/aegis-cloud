# ADR-0012: Score once after the run, attribute alerts by evidence time

* Status: accepted (amends ADR-0009)
* Date: 2026-10-31

## Context
Stage 2 looked for alerts about one second after each scenario, so any detector slower than that was scored as a miss although the window is 120 s. S02 and S07 both map to T1530, so an alert for one could be credited to the other.

## Decision
The runner records each scenario's start and end, waits `--settle` seconds after the last one, then scores once. Contract 1.1 adds `event_time`. An alert that carries it is credited only to the scenario whose interval contains that evidence time. `--rescore` re-scores a saved run without attacking again. Alerts that match no scenario are counted and printed as "other alerts".

## Consequences
* (+) Detector latency is measured as MTTD instead of being punished as a miss.
* (+) Same-technique scenarios cannot steal each other's alerts.
* (-) The baseline predates this change. It had no alerts, so it scores identically under both matchers.
* (-) Host and LocalStack clocks must agree to within `--slop` (default 1 s). The probe measures the difference.