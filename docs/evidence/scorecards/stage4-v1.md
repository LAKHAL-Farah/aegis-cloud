# Response scorecard: stage4-v1

_Generated 2026-11-04 03:15 UTC_

**Contained and independently verified: 2 of 2  |  attack to contained: mean 12.4 s, worst 14.5 s  |  of which machine time: 0.3 s  |  (simulated approval, 0 s human time)**

> The approval in this run was automated. The time to respond here is what the machines need; a person tapping Approve adds their own reaction time (see `human_wait_s` in a Telegram run).

| Playbook | Scenario | ATT&CK | Detected by | MTTD | Approval wait | Detected to contained | Attack to contained | Status | State verified |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| leaked_key | S11 | T1555.006 | AEG-CRED-001 | 10.0 s | 0.0 s | 0.3 s | 10.4 s | CONTAINED | yes |
| public_bucket | S07 | T1530 | AEG-EXFIL-002 | 14.2 s | 0.0 s | 0.2 s | 14.5 s | CONTAINED | yes |

## Notes

* `Attack to contained` runs from the first API call of the attack to the moment containment finished.
* `State verified` is checked by the measurer's own admin client after the responder finished: the responder's own verify step is not taken on trust.
* The range is restored after each pair, so one pair's containment never affects the next attack.
