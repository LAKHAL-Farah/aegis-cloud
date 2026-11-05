# Operations contract (Stage 5)

What the watchdog, the SLO report and the chaos harness read, and who writes it. Change a format here first, then the
code; `ops/tests/test_contract.py` and `ops/tests/test_slo.py` pin it.

## Heartbeat (written by the detector and the responder, read by the watchdog)
File `build/ops/heartbeats/<component>.json`, rewritten atomically (temp file + rename) every loop:

```json
{"component": "detector", "ts": 1793880000.12, "pid": 4242, "seq": 981}
```
`ts` is epoch seconds. A component is **up** when `now - ts` is within its limit (detector 20 s, responder 10 s) AND `pid`
exists. A stuck process (alive, not beating) is down; a dead one with a fresh file is down. The two writers
(`detections/aegis_detect/heartbeat.py`, `response/aegis_respond/heartbeat.py`) are byte-identical copies, tested as such,
because the responder also ships as a Lambda package and must not import the detector.

## Watchdog log (written by the watchdog, read by the SLO report)
`build/ops/health.jsonl`, one line per check:
`{"ts": 1793880005.0, "components": {"detector": {"up": true, "detail": "beat 1.2 s ago, pid 4242"}, "localstack": {...}}}`

`build/ops/events.jsonl`, one line per healing action: `{"ts", "component", "action": "restart" | "gave-up" | "publish-failed" | "chaos-start" | "chaos-end", "ok", "detail", "was"}`.
The chaos harness brackets each experiment with `chaos-start` / `chaos-end`; the SLO report leaves those windows out because the outage was caused on purpose.

## What the SLO report reads elsewhere
* the responder audit trail (`outcome` records, `data.timings.machine_s`), see `docs/response-playbooks.md`;
* ASFF findings: `CreatedAt` minus `ProductFields["aegis/event_time"]`, see `docs/detection-contract.md`.

## Checkpoint (written and read by the detector only)
`build/ops/detector-state.json`: `{"version": 1, "sources": {"<name>:<account>": {...}}, "engine": {"seen": [...], "last": {...}}}`.
A file with another `version`, or one that does not parse, is treated as absent (the detector starts "from now" and says so);
it never crashes the detector. Written after the sinks each poll, so a crash repeats an alert and never loses one (ADR-0018).
