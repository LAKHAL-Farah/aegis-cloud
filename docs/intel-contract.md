# Stage 6 contract: snapshots, scans, notes

Three small formats connect the Stage 6 parts to each other and to Stage 3 and 4. Change one and the tests that read it fail.

## IAM snapshot (`aegis.iam-snapshot/v1`)

Written by `sentinel.py collect`, read by everything else in Sentinel. Plain JSON.

| Field | Meaning |
| --- | --- |
| `account_id` | the account the snapshot describes |
| `collected_at` | UTC time of the read |
| `principals` | map from ARN to `{kind: user\|role\|group, name, boundary, trust, groups, inline, attached}` |
| `policies` | map from policy ARN to `{name, doc, aws_managed, bundled, approximate?, other_versions}` |
| `unresolved` | attached policies that could not be read. They count as granting nothing, and the scan says so |
| `warnings` | for example a boundary that could not be confirmed |

Only `Get*` and `List*` IAM calls produce it. AWS-managed policies are read through the API when possible, otherwise from a small
bundled table (`approximate: true` where the table is a simplification).

## Scan (`aegis.sentinel-scan/v1`)

Written by `sentinel.py scan --write` to `build/sentinel/scan.json`, read by triage.

* `accounts.<id>.principals.<arn>`: `{name, kind, category, hops, path, capped, boundary}`
* `category` is one of `admin` (standing `Allow * on *`, not expected), `expected_admin` (matches `sentinel/policy.json`), `escalates`
  (a path to admin exists), `capped` (an escalation technique exists but a permission boundary caps it), `ordinary`
* `path` is a list of steps `{from, to, technique, label, attack, conditional, kind}`; `technique` is a key of `escalation.CATALOGUE`
* A scan older than 24 hours is ignored by triage and reported as "unknown"

Posture findings written beside it (`build/sentinel/findings/`) are ASFF with `GeneratorId aegiscloud/sentinel/AEG-IAM-001` (escalation) or
`AEG-IAM-002` (standing admin) and `aegis/kind: posture`. They are not incidents and are never written to `build/findings/`.

## Triage note

Produced by `aegis_triage.graph.triage()`. What the approver sees is `TriageNote.advice_lines()`:

* at most four lines, each at most 260 characters, each starting `[triage`
* line 1: `[triage, advisory only, words by model|template]`, then priority and a one-sentence summary; line 2: the proposal; line 3: the evidence used; line 4 (optional): what to check next
* `action` is one of `contain_via_playbook`, `escalate_to_human`, `monitor`. It is decided by code, never by a model (ADR-0020)
* `explainer` says who wrote the words: `template`, `anthropic`, or `template (fallback: <reason>)`

The responder appends these lines after the plan (`Responder(advisor=...)`, `respond.py --advisor triage`). They are not part of the plan that runs.
