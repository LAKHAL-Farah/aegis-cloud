# Runbooks

One page per alarm or failure. Every alarm's description names its runbook (`ops/tests/test_runbooks.py` fails if one
is missing), and every runbook has the same four parts: **Symptom**, **Check**, **Fix**, **Verify**.

| Page | When |
| --- | --- |
| [cis-alarm.md](cis-alarm.md) | any `aegis-cis-4_*` alarm (CIS section 4) |
| [detector-down.md](detector-down.md) | `aegis-pipeline-detector-down`, or `make ops-status` shows the detector DOWN |
| [responder-down.md](responder-down.md) | `aegis-pipeline-responder-down`, or incidents stop getting approval requests |
| [watchdog-gave-up.md](watchdog-gave-up.md) | `events.jsonl` shows `gave-up`: a component keeps dying |
| [restore-from-versions.md](restore-from-versions.md) | objects deleted or overwritten in a versioned bucket (S10, S12) |

Reading order for an incident: what broke (this table) -> what the audit trail says
(`build/ops/response/audit.jsonl`, `python3 response/respond.py audit`) -> fix -> verify -> write what you learned in
`docs/threat-model.md` or an ADR if it changes a decision.
