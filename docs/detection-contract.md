# Detection contract (Stage 2 <-> Stage 3)

Any detector (Wazuh active response, the Python/ASFF engine, Falco, a human analyst testing a
rule) proves it caught an attack by writing one JSON file per alert under `build/alerts/`
(configurable with `run_attacks.py --alert-dir`). `run_attacks.py` reads every `*.json` file in
that directory after each scenario; a file may contain a single object or a list of objects.

## Required fields

| Field | Type | Meaning |
| --- | --- | --- |
| `technique` | string | MITRE ATT&CK technique ID, e.g. `"T1562.008"`. Must match a scenario's `technique` exactly. |
| `account_id` | string | The 12-digit account the alert is about. Must match the attacked account (the **purple** twin's id during a normal run; ADR-0009 scores against purple only, since the hardened twin is meant to prevent, not merely detect). |
| `detected_at` | string | ISO-8601 UTC timestamp, e.g. `"2026-10-30T14:03:22Z"`, of when the detector raised the alert (not when the attack happened). |

## Recommended fields

| Field | Type | Meaning |
| --- | --- | --- |
| `source` | string | Which detector: `"wazuh"`, `"python-engine"`, `"falco"`. |
| `summary` | string | One line a human reads in the scorecard, e.g. `"CloudTrail: StopLogging by dev-svc"`. |
| `rule` | string | The rule or detection ID that fired. |
| `severity` | string | `"low"` / `"medium"` / `"high"` / `"critical"`. |
| `raw_event_id` | string | CloudTrail `eventID` or similar, for drill-down. |

## Matching rule (ADR-0009)

An attack on a given scenario is **DETECTED** if at least one alert file exists with the same
`technique` and `account_id`, and `detected_at` falls within `[attack_start - 1s, attack_start +
window]` (`window` defaults to 120 seconds). The earliest such alert is used; its time minus the
attack's start time is the scenario's **MTTD**.

## Minimal example

\`\`\`json
{
  "technique": "T1562.008",
  "account_id": "555555555555",
  "detected_at": "2026-10-30T14:03:22Z",
  "source": "python-engine",
  "summary": "CloudTrail StopLogging called by dev-svc",
  "severity": "critical"
}
\`\`\`

## Guarantees `run_attacks.py` makes to detector authors

* The attacker identity is always the twin's `dev-svc` user (or the account root with
  `--as-root`); Stage 3 rules can key off that identity without guessing.
* `build/alerts/` is never cleared by the runner. A detector owns writing and rotating its own
  files; the runner only reads.
* Scenarios run **sequentially** with cleanup between each, so a detector almost never needs to
  disambiguate two concurrent attacks (the one documented exception is S02/S07, both `T1530`:
  see `cloudpurple/tests/test_catalogue.py`).  