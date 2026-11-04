# Stage 4 predictions (written before the first measured run)

Commit this file before `docs/evidence/scorecards/stage4-v1.*` exists, as with Stage 3.
After the run, add a "predicted vs actual" line under each item. Do not edit the predictions.

1. **Both pairs end CONTAINED and independently verified (2 of 2).** The two playbooks only use IAM and S3 calls that
   LocalStack supports. Confidence: medium-high.
2. **Detection is not the slow part this time, delivery latency is.** MTTD about 0.4 to 3 s for both, unless the first pair
   waits for the first CloudTrail flush (Stage 3 measured about 14 s for the first scenario). Confidence: medium.
3. **Machine time (detected to contained) under 2 s per pair.** About five to seven local API calls plus a Secrets Manager write.
4. **Attack to contained with simulated approval: 3 to 8 s typical, up to about 16 s for the first pair.** The 90 second
   goal is not at risk from the machines. It depends on the person tapping Approve.
5. **The first real run will break something small.** Candidates: (a) the finding's principal is not a user ARN on
   LocalStack, so the playbook refuses; (b) the replacement-key secret name is rejected; (c) the range's
   `dev-svc` already has two keys, so rotation is skipped. Each of these is handled with a clear message, not a crash.
6. **LocalStack will still accept calls made with the deactivated key.** Not asserted by the scorecard, because the claim
   would be about LocalStack's IAM enforcement and not about the playbook.
7. **No extra incidents.** The responder should raise no response to findings from other scenarios, because only three
   rules map to `leaked_key` and one to `public_bucket`, and the run touches two scenarios.
