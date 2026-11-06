# Chaos run stage5-v3

| Experiment | Resume | Outage noticed | Restart to up | Verdict | What happened |
| --- | --- | --- | --- | --- | --- |
| detector-kill | on | 0.5 s | 10.6 s | **SURVIVED** | the attack made while the detector was down was detected after recovery |
| responder-kill-pending | on | 0.0 s | 2.0 s | **SURVIVED** | interrupted mid-approval, asked again after restart, contained and verified |
