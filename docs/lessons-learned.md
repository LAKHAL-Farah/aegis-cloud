# Lessons learned

Everything here happened in this repository and is recorded somewhere else too (a prediction file, an ADR, an evidence
file). This page collects it so a reader does not have to dig. It says what went wrong and what changed, not only what
worked. Where a cause is a guess, it says so.

## 1. What the predictions got wrong

The project writes predictions before it measures (`docs/stage*-predictions.md`). The misses are the useful part.

| Stage | Prediction | What happened | What it taught |
| --- | --- | --- | --- |
| 4 | Attack to contained, simulated approval: 3 to 8 s | 10.4 s and 14.5 s on the first run | The slow part was log delivery, not code. The machine time was 0.2 to 0.3 s. Measure each leg separately or the wrong leg gets optimised |
| 4 | "The first live run breaks something small" | Nothing broke | A prediction that something will break is still a prediction. Writing it down did not make it true |
| 5 | A killed process is noticed within 0.5 s | Noticed after 0.0 s (detector) and 10.1 s (responder) in the first valid run, equal to the heartbeat limits | The pid check did not see the dead process (a zombie is the likely cause, not verified). Later runs notice within 0.5 s; what changed between them has not been checked here |
| 5 | After a restart the responder asks again within 3 s and contains within 2 s | 8.6 s and 10.2 s (stage5-v3) | Still unexplained: it is not known what the first number is measured from |
| 5 | Restore drill under 2 s | 3.4 s and 3.6 s | Passed 6 of 6 objects, so the recovery works; the estimate of how long it takes was optimistic |

## 2. Incidents and fixes

### 2.1 A hidden setting flipped a security result (Stage 2)

Two runs of the same SCP test gave "not enforced" and then "enforced". The difference was `ENFORCE_IAM=1`, which had not been set
for the first run, and the first run also used the member account's root user. Recorded in `docs/localstack-limitations.md`.
**Rule that came out of it:** write the setting next to every enforcement claim. The cause is "probable", not isolated by a
controlled on and off test, and the document says so.

### 2.2 Scoring too early punished a slow detector (Stage 2 to 3, ADR-0012)

The first scorer looked for alerts one second after each attack. Any detector slower than that was scored as a miss although the
window was 120 s. Two scenarios share a technique (T1530), so an alert for one could be credited to the other. **Fix:** record
each scenario's interval, score once after a settle period, and credit an alert only to the scenario whose interval contains the
evidence time. Latency became MTTD instead of a miss.

### 2.3 A detector that knows the test proves nothing (ADR-0013)

A detector tuned to the attack harness would score 12 of 12 and mean nothing. **Fix:** rules are written from the behaviour each
scenario describes, and a test fails the build if detection code mentions a scenario id, a run id, the harness's user agent or
the range's account ids and resource names. The one policy-based rule (`AEG-ACCESS-001`) is labelled as the weakest detection.
Stage 6 reuses the same test shape for Sentinel and triage.

### 2.4 One scenario cannot be observed on this emulator (ADR-0014)

S08 (a leaked key used from a new client) depends on the user agent and source address. LocalStack records
`console.amazonaws.com` and `1.2.3.4` for every caller, so the signal never reaches the log. Counting it as a miss would have said
something about the emulator, not about the detections. **Fix:** it still runs and is still shown, but it leaves the scorable
denominator, so the result reads "11 of 11 scorable (12 run, S08 excluded)". The headline number in the README always carries
both figures.

### 2.5 The first chaos run was invalid (Stage 5)

The first baseline attempt (`stage5-v1*`) was not a valid test and is kept only as a record. It was repeated as v2 and v3, and
the baseline (no fixes) loses the event while the run with checkpoint and resume survives it. Keeping the invalid run visible is
deliberate: deleting it would make the series look cleaner than it was.

### 2.6 The headline response run used a simulated approval (Stage 4 to 7)

The run that gives "2 of 2 contained, 12.3 s from attack" used an automatic approver (`approver: auto`, human wait 0.0 s). A
run with a person at a terminal exists (17.6 s and 9.5 s, of which 15.4 s and 7.3 s was the wait). A first draft of the CV line in
Stage 7 said "contained with human approval in Slack", which the evidence does not support. **Fix:** the CV line and the README
numbers are now generated from the evidence files (`make portfolio`), including the word "simulated", and `make docs-check`
fails if the README disagrees with the evidence. No approval has been measured through Slack itself.

### 2.7 Two responders broke the audit chain (found live, Stage 6, ADR-0023)

The first live approval with the triage note showed the triage lines correctly, and then `make respond-audit` printed `CHAIN BROKEN`.
The records showed a key deactivated twice, a replacement key that failed (`LimitExceeded`) and then succeeded, and two outcomes for
one incident. More than one executing responder was alive: `make respond-up` had been run several times, each run started a new process
and overwrote the pid file, and `respond-down` stopped only the last one. This was an existing Stage 4 hazard, not part of the Stage 6
code, and no test could have found it because every test runs one responder. **Fix:** an exclusive lock per state directory, guards in
the make targets, and tests that start a real second process. **Rule:** whatever acts must be provably single; a hash chain
noticing the problem afterwards is the last line of defence, not the first.

### 2.8 Seven things the Stage 6 and 7 work found in its own code

* **A fake test universe hid a real bug.** IAM calls it `s3:ListAllMyBuckets`; the botocore operation is `ListBuckets`. With a
  hand-made action list that contained the IAM name, the tests passed. With the real list the action counted as nothing and a
  user looked fully reduced. Fixed, and pinned by a test against the real s3 model.
* **A safety test was weaker than it looked.** The hostile string used to test the triage sanitiser contained a `/`, and identity
  extraction splits on `/`, so the hostile part was discarded before it reached the code under test. Three deliberate breakages of
  the sanitiser still passed. Found only by breaking the code on purpose and seeing nothing fail. **Rule:** a safety test is not
  trusted until the thing it guards has been broken and the test noticed.
* **The emulator drops fields.** moto omits `PolicyName` in the account authorisation listing and drops a user's permission
  boundary. A dropped boundary overstates what a user can do, so the collector now asks for each principal's boundary directly.
* **A checksum file held an absolute path.** `package_lambda.sh` wrote `<hash>  /full/path/aegis-respond.zip`, so
  `sha256sum -c` checked the original file even when a copy had been tampered with. The signature check would have caught it, but
  the checksum was lying. Fixed at the source and pinned by a test that tampers with a copy.
* **A make target depended on the caller's shell.** The Sentinel targets set an access key (the account id) but not a secret, and
  worked only after `source scripts/env.sh`. The first live attempt failed with "partial credentials". The targets now set what they
  need. A test environment that already has the variables hides this kind of bug, so the fix was checked with the variables removed.
* **A claim about a tool's versions was wrong.** The release notes said cosign v2 or v3. Local-key signing used a v3-only flag, so on v2
  (what a distribution package may install) it would have failed. Found by downloading a real v2 and running the tests against both;
  the script now detects the version. Both v2.5.3 and v3.1.4 pass.
* **The SBOM used the wrong key.** Validating it against the official CycloneDX 1.5 schema showed `aggregates` should be
  `aggregate`. `make sbom-validate` repeats the check.

## 3. Habits worth keeping

1. **Predict, then measure, then keep the wrong predictions.** The wrong ones are where the learning is.
2. **Name the denominator.** "11 of 12" and "11 of 11 scorable" are different claims. Both are printed.
3. **Break the guard on purpose.** Mutation checks found three weak tests in Stage 6 that a green run did not.
4. **Make the documents check themselves.** The README's numbers, the architecture's file paths and the ADR numbering are tests.
5. **Say "simulated" where it is simulated.** The approval, the accounts and the whole cloud are emulated.

## 4. What I would do earlier next time

* Run the real action list and the real emulator against new code on day one, not after the unit tests are green.
* Decide at the start which claims need a real person in the loop, and measure those first.
* Write the limitations page while building, not afterwards. The best entries (2.1, 2.4) came from noticing a surprise and writing it down the same day.
