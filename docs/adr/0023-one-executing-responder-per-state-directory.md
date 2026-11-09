# ADR-0023: One executing responder per state directory

* Status: accepted
* Date: 2026-11-08

## Context
During the first live run of the Stage 6 triage note, one approval produced this audit trail: a key deactivated twice, a
replacement key that failed with `LimitExceeded` and then succeeded, two `verify` records with the same sequence number, and two
outcomes for one incident (`contained` and `partial`). `make respond-audit` then reported `CHAIN BROKEN`.

Cause: more than one executing responder was running. `make respond-up` started a new process every time and overwrote the pid
file, so each earlier start (four in that session) stayed alive, and `make respond-down` stopped only the one in the pid file. Every
responder watching the same findings directory handled the same incident. The audit log serialises writers with a lock that only
exists inside one process, so two processes interleaved their records and broke the hash chain. Nothing in the triage code was involved.

## Decision
1. **An executing responder takes an exclusive OS file lock** (`aegis_respond/singleton.py`) keyed by its state directory, and refuses to
   start if it is held, printing the holder's pid. The lock is released by the OS when the process ends, however it ends.
2. **The lock file lives in the system temp directory**, because the state directory may be on a mount where `flock` is unreliable.
3. **Only executing responders are exclusive.** A dry-run watcher only plans, so it may run beside one.
4. **The make targets guard the same thing from outside.** `respond-up` and `detect-up` refuse if a matching process exists, and
   `respond-down` and `detect-down` stop every matching process, not only the one in the pid file.
5. **The audit log stays as it is.** A broken chain is evidence, and is never repaired. The broken file is kept and a new audit
   file is started.

## Consequences
* (+) The failure cannot recur through the normal commands, and a second start says why it was refused.
* (+) The ops watchdog, which restarts the responder, now fails loudly instead of creating a second one.
* (-) `flock` is advisory and per machine: it does not protect against two machines sharing one state directory. The Lambda path is
  a separate design with its own claim mechanism.
* (-) The audit log is still safe only with a single writer. This ADR enforces that; it does not make the log multi-process safe.
* (-) The detector is guarded only by the make targets, not by a lock in the code. Two detectors duplicate findings rather than act twice.
