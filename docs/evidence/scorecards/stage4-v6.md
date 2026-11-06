# Response scorecard: stage4-v6

_Generated 2026-11-06 01:18 UTC_

**Contained and independently verified: 2 of 2  |  attack to contained: mean 12.3 s, worst 14.4 s  |  of which machine time: 0.2 s  |  (simulated approval, 0 s human time)**

> The approval in this run was automated. The time to respond here is what the machines need; a person approving adds their own reaction time (see `human_wait_s` in a file or Slack run).

| Playbook | Scenario | ATT&CK | Detected by | MTTD | Approval wait | Detected to contained | Attack to contained | Status | State verified |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| leaked_key | S11 | T1555.006 | AEG-CRED-001 | 9.9 s | 0.0 s | 0.3 s | 10.2 s | CONTAINED | yes |
| public_bucket | S07 | T1530 | AEG-EXFIL-002 | 14.3 s | 0.0 s | 0.1 s | 14.4 s | CONTAINED | yes |

## Notes

* `Attack to contained` runs from the first API call of the attack to the moment containment finished.
* `State verified` is checked by the measurer's own admin client after the responder finished: the responder's own verify step is not taken on trust.
* The range is restored after each pair, so one pair's containment never affects the next attack.
