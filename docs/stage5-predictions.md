# Stage 5 predictions (written before the first measured run)

Commit this file before `docs/evidence/chaos/stage5-*.md`, `docs/evidence/ops-probe.md` and `docs/evidence/restore-drill.json`
exist, as with Stages 3 and 4. After the runs, add a "predicted vs actual" section below the line. Do not edit the predictions.

Runs: `make ops-probe WAIT=150`, then `make stage5-run LABEL=stage5-v1-baseline NORESUME=1`, then
`make stage5-run LABEL=stage5-v1`, then `make ops-drill`, then `WRITE=1 make ops-slo`.

1. **Baseline (no checkpoint, no resume): `detector-kill` ends EVENT LOST.** The restarted detector primes "from now". Confidence: high.
2. **With checkpoint: `detector-kill` ends SURVIVED** and the gap attack (S01) is detected after recovery. Confidence: medium-high. What would make me wrong: the trail file holding the gap event is flushed before the kill and the baseline accidentally catches it, or the first resumed poll hits a lookup/S3 error.
3. **A killed process is noticed within 2 s by the probe** (the pid is gone; no need to wait for the 20 s heartbeat limit). The watchdog adds up to its interval (5 s). A hung (not killed) process would take up to 20 s; not tested.
4. **Recovery (kill to fresh heartbeat) in 4 to 12 s.** Process start, S3 listing, checkpoint restore and one poll. The restart waits for the first heartbeat, so it includes the first poll.
5. **Baseline: `responder-kill-pending` ends EVENT LOST** (nobody asked again: the claim makes it a duplicate, and the watch ignores files on disk). Confidence: high.
6. **With resume: `responder-kill-pending` ends SURVIVED:** asked again within 3 s of the restart, contained within 2 s of approval. Confidence: medium. The harness approves the pending request itself, so this proves recovery, not a human's reaction time.
7. **Restore drill: PASS, 6 of 6 objects bit for bit, RTO under 2 s.** Medium-high. Risk: the data bucket's KMS default encryption or LocalStack's version timestamps (one-second granularity, handled by a 1.1 s settle) behave differently from moto.
8. **Probe: CloudWatch custom metrics WORKS; alarm evaluation STORED ONLY** (set_alarm_state works, alarms do not move on their own, so the missing-data dead-man's switch is untestable here). **CloudTrail to CloudWatch Logs delivery: STORED ONLY or NOT SUPPORTED.** SSM Run Command: STORED ONLY. Backup jobs: 50/50 between STORED ONLY and WORKS. Metric filters firing: 60% STORED ONLY.
9. **The SLO report will say "not enough events" for the response and freshness SLOs** after one run (a handful of incidents) and show availability near 100% only if the watchdog ran for the whole time. That is the honest output; a 24 h unattended run is the real test.
10. **The first live run breaks something small.** Candidates: (a) applying the management root with `enable_cloudwatch_logs = true` is rejected by LocalStack's CloudTrail (then set it to false, record the failure in `localstack-limitations.md`, and 3.4 / 4.x stay "definitions verified by terraform test only"); (b) `backup` endpoint or `aws_backup_*` provider reads fail (then `enable_backup` stays false); (c) the S3 drill's `copy_object` of a specific version is rejected for SSE-KMS objects.
11. **No new detections and no change to the Stage 3 and 4 scorecards.** The checkpoint and resume options are off for those runs. Re-running `stage3-run` and `stage4-run` must reproduce their committed scorecards (within normal timing noise).
