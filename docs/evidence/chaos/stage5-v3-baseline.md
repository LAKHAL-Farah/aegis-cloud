# Chaos run stage5-v3-baseline

| Experiment | Resume | Outage noticed | Restart to up | Verdict | What happened |
| --- | --- | --- | --- | --- | --- |
| detector-kill | off | 0.5 s | 11.1 s | **EVENT LOST** | the attack made while the detector was down was never detected: the outage window is a blind spot |
| responder-kill-pending | off | 0.0 s | 2.0 s | **EVENT LOST** | after the restart nobody was asked again: the incident was silently dropped |
