# ADR-0020: Triage: code decides, a model may only explain, and the result is advisory

* Status: accepted
* Date: 2026-11-06

## Context
Stage 6 asks for an agent that triages alerts and feeds the approval flow. Three things make that risky: the finding contains
strings an attacker chose (principal names, bucket names, user agents), a model can be talked into anything by text it reads,
and the approval step exists precisely so that nothing changes without a person. An agent that could influence which action runs
would turn a prompt-injection into a containment decision.

## Decision
1. **Code decides priority and action.** `assess.py` computes a priority from severity, related findings, and what IAM Sentinel
   says about the principal. `propose` returns one of three actions (`contain_via_playbook`, `escalate_to_human`, `monitor`) and
   only ever names a playbook the responder policy already enables. A protected identity always gets `escalate_to_human`.
2. **A model, if configured, writes words only.** It receives the decision as context and returns a short summary and up to
   three "check next" items. It has no tools. The module cannot import AWS clients, call a playbook, or touch the network outside
   `explain.py`; tests check this.
3. **Everything an attacker controls is sanitised before use** (control and invisible characters, markup, mentions, anything shaped
   like a link or a credential), and only a short tail of ARNs is shown.
4. **Model text is validated.** Wrong shape, too long, a link, a mention, a credential shape, an emoji code, or markup, and it is
   discarded. The deterministic template is shown instead and the note says why (`template (fallback: ...)`).
5. **The model is off by default.** It runs only when `AEG_TRIAGE_LLM=anthropic`, a key, and `AEG_TRIAGE_MODEL` are all set. There
   is no default model name, so nothing stale is baked in. A call has a short timeout (3 s by default) and no retries.
6. **The runtime is LangGraph if installed, a 20-line runner if not.** The nodes are the same functions, and a test checks both
   give the same note.
7. **The responder hook is display-only.** `Responder(advisor=...)` appends lines after the plan. They are not part of the plan, an audit
   record (`advice`) is added, an advisor that raises is dropped, and `contain()` still receives the exact plan the person saw.

## Consequences
* (+) A hostile name cannot change a decision, and the tests show it, including by breaking the sanitiser on purpose.
* (+) A broken, slow or absent model costs a few milliseconds, not an incident.
* (-) With the model on, sanitised finding facts leave the machine. The default avoids that.
* (-) A well-formed but misleading model sentence can still reach a person. The note is labelled advisory and sits after the plan,
  but this is not solved, only bounded.
* (-) Only a fake model has been tested. No live model run is part of these results, and nothing here measures whether the note
  helps a person decide faster.
