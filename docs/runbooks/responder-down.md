# The responder is down

## Symptom
`make ops-status` shows `DOWN responder`, the alarm `aegis-pipeline-responder-down` fired, or findings appear in
`build/findings` but nobody is asked to approve anything.

## Check
1. `make ops-status`, then `tail -n 40 build/ops/responder.log`.
2. What was it doing? `python3 response/respond.py --state-dir build/ops/response audit` shows incidents with `received` and no `outcome`: those were interrupted mid-approval.
3. Pending approval requests are files under `build/ops/response/approvals/`.

## Fix
`make ops-up`. The responder starts with `--resume`: findings that arrived while it was down and incidents it was killed
in the middle of are handled again (the person is asked again), incidents already closed are not repeated, and
findings older than 15 minutes are left alone (`--resume-max-age`). Do not start it with `--replay`: that re-handles
every old finding, including closed ones.

## Verify
`make ops-status` all UP; the audit shows a `resumed` record for each interrupted incident and then an `outcome`.
