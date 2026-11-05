# Chaos run stage5-v2-baseline

| Experiment | Resume | Outage noticed | Restart to up | Verdict | What happened |
| --- | --- | --- | --- | --- | --- |
| detector-kill | off | 17.2 s | 11.1 s | **EVENT LOST** | the attack made while the detector was down was never detected: the outage window is a blind spot |
| responder-kill-pending | off | 10.1 s | 2.5 s | **EVENT LOST** | after the restart nobody was asked again: the incident was silently dropped |
