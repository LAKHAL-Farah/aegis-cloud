# The watchdog gave up restarting a component

## Symptom
`build/ops/events.jsonl` has `"action": "gave-up"`: the component died 3 times in 10 minutes and the watchdog stopped
restarting it. A restart loop hides a bug and can hammer LocalStack, so a person decides.

## Check
1. `cat build/ops/events.jsonl`: which component, and what its `was` field said each time (stale beat vs dead pid).
2. The component's own log: `build/ops/<component>.log`. Look for the first error after each start, not the last line.
3. Is something external down (LocalStack, disk, network)? `make ops-status` shows LocalStack and OpenSearch too.

## Fix
Repair the cause, then `make ops-up` (a manual start is not rate-limited). Restart the watchdog (`make ops-watchdog`) to reset its budget.

## Verify
Ten quiet minutes with no new `restart` events, and the SLO "Detection path is up" stops dropping.
