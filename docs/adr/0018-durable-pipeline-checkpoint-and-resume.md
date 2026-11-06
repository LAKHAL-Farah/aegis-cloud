# ADR-0018: A restarted detector and responder resume, delivery is at-least-once

* Status: accepted
* Date: 2026-11-05

## Context
Reading the Stage 3 and 4 code for Stage 5 showed two ways the pipeline silently loses work when a process dies:
1. The detector starts "from now" (`prime()` marks every existing trail file as read). Anything delivered while it was down is skipped forever.
2. The responder ignores findings already on disk at start, and its ledger claims an incident BEFORE the person is asked. Killed while a person is deciding, it restarts, sees the claim and calls the finding a duplicate: the incident is dropped with no error.

Neither was a bug in the stages' own scope (the measured runs never kill anything). Both are bugs for anything that runs unattended.

## Decision
* **Detector checkpoint** (`--state-file`, opt-in): after each poll, after the sinks, the detector atomically saves what it has read
  (S3 object keys, the lookup cursor) and what it has already emitted (recent event ids, cooldown clock). On start with a
  readable checkpoint it restores instead of priming. A missing, corrupt or foreign-version file means "from now", loudly.
* **Responder resume** (`--resume`, opt-in): the audit trail is the truth. An incident with a `received` record and no
  `outcome` or `skipped` was interrupted: its ledger claim (and the cooldown that claim wrote) is released, an audit record
  `resumed` is written, and the finding is handled again, so the person is asked again. Closed incidents are skipped. Findings
  older than `--resume-max-age` (15 minutes) are ignored so a long outage or an old findings folder does not flood a person with approvals for a world that moved on.
* **At-least-once.** A crash between emitting an alert and saving the checkpoint repeats that alert after restart; the
  responder's ledger absorbs repeats. The alternative (save before emit) could lose one, and a lost detection is worse than a repeated one.
* **Not saved:** rule windows (sliding-window correlation). After a restart those rules see only events processed since,
  so a correlation that straddled the crash can be missed. Recorded in the limitations file.
* **The measured Stage 3 and 4 runs are untouched:** both options are off unless asked for, so the committed scorecards remain reproducible.

## Consequences
* (+) The two losses are tested at unit level (`detections/tests/test_checkpoint.py`, `response/tests/test_recovery.py`, each including the failure mode as a regression marker) and at system level by the chaos experiments, run once without and once with the fix so the improvement is measured, not asserted.
* (+) The checkpoint stores keys and timestamps only, no event bodies.
* (-) The checkpoint's key list grows with the number of trail files. Fine for a lab run of days, a known cost beyond that (prune by prefix date if it ever matters).
* (-) `--resume` handles an incident that the person already half-decided; they are asked again. Asking twice is the safe side of that coin.
