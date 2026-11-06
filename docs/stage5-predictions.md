## Predicted vs actual (stage5-v2-baseline, stage5-v2, ops-probe, SLO)

1. Baseline detector-kill ends EVENT LOST. Actual: EVENT LOST. Right. (The first attempt, stage5-v1*, was invalid: see amendments.)
2. With checkpoint, detector-kill ends SURVIVED. Actual: SURVIVED. Right.
3. A killed process is noticed within 0.5 s. Actual: 0.0 s (detector), 10.1 s (responder), equal to the heartbeat limits. Wrong: the pid check did not catch the dead process (probable zombie, not yet verified).
4. Recovery in 4 to 10 s. Actual: 11.1 s (detector, inside the range), 2.5 s (responder, faster). Mostly right.
5. Baseline responder-kill-pending ends EVENT LOST. Actual: EVENT LOST. Right.
6. With resume, asked again within 3 s and contained within 2 s of approval. Actual: <read asked_again_s and contained_after_approval_s from stage5-v2.json>.
7. Item 7: drill passed 6/6, RTO 3.57 s and 3.43 s (predicted under 2 s).
