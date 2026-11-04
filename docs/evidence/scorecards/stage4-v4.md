# Response scorecard: stage4-v4

_Generated 2026-11-04 03:24 UTC_

**Contained and independently verified: 2 of 2  |  attack to contained: mean 13.5 s, worst 17.6 s  |  of which machine time: 0.2 s  |  (includes a real person's approval time)**

| Playbook | Scenario | ATT&CK | Detected by | MTTD | Approval wait | Detected to contained | Attack to contained | Status | State verified |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| leaked_key | S11 | T1555.006 | AEG-CRED-001 | 2.0 s | 15.4 s | 15.6 s | 17.6 s | CONTAINED | yes |
| public_bucket | S07 | T1530 | AEG-EXFIL-002 | 1.9 s | 7.3 s | 7.5 s | 9.5 s | CONTAINED | yes |

## Notes

* `Attack to contained` runs from the first API call of the attack to the moment containment finished.
* `State verified` is checked by the measurer's own admin client after the responder finished: the responder's own verify step is not taken on trust.
* The range is restored after each pair, so one pair's containment never affects the next attack.
