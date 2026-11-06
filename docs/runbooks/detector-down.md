# The detector is down

## Symptom
`make ops-status` shows `DOWN detector`, or the alarm `aegis-pipeline-detector-down` fired, or the SLO "Detection path is up" is dropping.
**Attacks in this window are invisible until the detector is back.** With checkpointing (ADR-0018) they are read after
the restart; without it they are lost.

## Check
1. `make ops-status`: is it "no heartbeat file", "heartbeat N s old" (stuck) or "pid is gone" (dead)?
2. `tail -n 40 build/ops/detector.log` for the last words. Common: LocalStack unreachable (`make up`), a bad rule file, disk full.
3. Is the watchdog running? `build/ops/health.jsonl` should have a line every few seconds. If not, nothing is healing.
4. Did it give up? `grep gave-up build/ops/events.jsonl` -> [watchdog-gave-up.md](watchdog-gave-up.md).

## Fix
`make ops-up` (restarts any component whose heartbeat is stale; a stuck copy is killed first). It resumes from
`build/ops/detector-state.json`, so the outage window is read, not skipped. Never `rm` that file to "fix" a problem:
the next start would be "from now" and the gap would be lost.

## Verify
`make ops-status` is all UP, and the log says `RESUMED 1 source(s) from checkpoint`. To prove the gap closed, check that
findings dated inside the outage now exist in `build/findings`.
