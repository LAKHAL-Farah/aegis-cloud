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

---

## Predicted vs actual (stage4-v1 simulated approval, stage4-v4 approval at the terminal)

Figures marked ~ are derived from the scorecards: attack-to-contained minus approval wait minus machine time.

1. **Both pairs CONTAINED and independently verified.** Actual: 2 of 2 in both runs. Right.
2. **Delivery latency is the slow part; MTTD 0.4 to 3 s unless the first pair waits for the first flush.** Actual: detection plus
   log delivery was ~10 s and ~14 s in stage4-v1 and ~2 s for both pairs in stage4-v4. Partly right: the long delay is real and
   is delivery, but it hit both pairs in v1 and neither in v4, so it is a range, not a first-pair effect.
3. **Machine time under 2 s per pair.** Actual: 0.3 s (v1) and 0.2 s (v4). Right.
4. **Attack to contained, simulated approval: 3 to 8 s typical, up to ~16 s for the first pair.** Actual (v1): 10.4 s and 14.5 s,
   the second pair slower. Wrong on the typical figure: 3 to 8 s did not happen. The ~16 s ceiling held.
5. **The first live run breaks something small.** Actual: nothing did. The principal was an IAM user ARN, the secret name was
   accepted, and `dev-svc` had one key. Wrong.
6. **LocalStack keeps accepting calls from the deactivated key.** Not tested, as predicted.
7. **No extra incidents.** Actual (v4 audit): exactly two `received` records. Right.

With a person approving at the terminal (v4): attack to contained 17.6 s and 9.5 s, of which 15.4 s and 7.3 s was the approval
wait. The 90 second goal was met with a person in the loop; the person here was at a terminal prompt, not a phone.
