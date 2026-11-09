# Stage 6 predictions (written before the first run of IAM Sentinel or the triage agent)

Same rules as Stages 3 to 5: this file is committed before any Stage 6 evidence exists. After a run, add a
"predicted vs actual" line under each item below the rule. Do not edit the predictions.

Stage 6 has two parts and they are measured differently.

* **IAM Sentinel** reads IAM (a snapshot of the account), builds a graph, finds escalation paths and writes a
  least-privilege policy from observed CloudTrail usage. Offline it runs on snapshots and on moto. Live it runs
  against LocalStack (`make sentinel-scan`).
* **The triage agent** reads an ASFF finding and writes an advisory note into the approval prompt. It decides nothing.
  Offline it runs with a template explainer and with a fake model. A live model run is optional and is not part of
  these predictions.

1. **The purple twin has exactly one escalation path and one standing admin.** `intern` reaches admin in one hop
   (`iam:CreatePolicyVersion` on the policy attached to itself). `dev-svc` is already admin (`Allow * on *`, no
   boundary), so it is reported as standing admin, not as an escalation. No other principal appears. Confidence: high.
   The twin was written to contain exactly these two weaknesses (S09 walks the first).
2. **The hardened twin has zero escalation paths and no standing admin.** The permission boundary is an allow list
   (`ec2:*`, `s3:*`, `kms:*` ... and only `iam:Get*`, `iam:List*`, `iam:PassRole`), so the intersection removes
   `iam:CreatePolicyVersion` and `*`. Confidence: medium. The risk is my evaluator, not the twin: boundary
   intersection and `NotAction` (PowerUserAccess) are where a small IAM evaluator is usually wrong.
3. **A least-privilege policy generated from a run's CloudTrail removes at least 99% of what `dev-svc` is granted** and
   at least 50% of what `intern` is granted. The first figure is dominated by `*` expanding to the whole action
   universe, so it says "the wildcard was the problem", not "the generator is clever". Confidence: high for both,
   because the numbers follow from the arithmetic. The universe is an approximation (botocore operation names), and
   the report says so.
4. **Every successful observed call is still allowed by the generated policy (coverage 100%), and the escalation path
   for `intern` is gone after the swap.** Coverage is checked by running the evaluator over the new policy, not by
   assertion. Exceptions are calls that need no permission (`sts:GetCallerIdentity`), which are listed, not hidden.
   Confidence: high.
5. **The generator refuses to turn an attack into a permission.** If the observed window contains
   `iam:CreateAccessKey` or `cloudtrail:StopLogging` (the scenarios do), they are reported as "observed but sensitive"
   and left out unless `--keep-sensitive` is given. Confidence: high. It is a rule in the code, and a test.
6. **Triage proposes `contain_via_playbook` for exactly the rules the responder policy maps to a playbook, and for
   nothing else.** Everything else is `escalate_to_human` (high or critical) or `monitor`. A protected identity is
   always `escalate_to_human`. Confidence: high, because the proposal is deterministic code.
7. **Text an attacker controls cannot change a decision.** With principal names, bucket names and user agents that
   contain instructions, Slack mentions, links and a fake access key id, the priority and the proposed action are
   identical to the clean case, and none of those strings reach the note. Confidence: high for the template
   explainer. Medium for the model path, which is tested only with a fake model that misbehaves on purpose
   (invalid JSON, an action outside the list, a leaked key id, a mention). A live model is not tested here.
8. **A broken model never blocks an incident.** Timeout, bad JSON, or no API key all fall back to the template, and the
   fallback is recorded in the note (`explainer: template (fallback: ...)`). Confidence: high.
9. **The first live scan breaks something small.** Candidates: (a) `get_account_authorization_details` on LocalStack
   omits AWS-managed policy documents, so some attached managed policies are "unresolved"; (b) the account has
   principals created by other stages (monitoring, ops) that I did not model; (c) pagination marker handling.
   Each is reported ("N attached policies could not be resolved"), not crashed on. Confidence: low to medium.
   This one is only settled by `make sentinel-scan` on the real range.
10. **The advisor adds under 5 ms of work to an approval request when the model is off** and the approval flow is
    otherwise unchanged: the plan the person approves, the audit chain and the playbooks are byte-identical with the
    advisor on and off, apart from one extra audit record (`advice`). Confidence: medium-high.

What is deliberately not predicted: any mean-time figure for a live model, and any claim that the triage note
improves how fast a person decides. Both would need a live run with a person, and neither is measured here.

---

## Predicted vs actual (offline: moto twins, fake model; the live LocalStack run is `make sentinel-scan` and is not done yet)

Evidence: `docs/evidence/sentinel-offline.md` and `docs/evidence/triage-eval.md` (`make triage-eval WRITE=1`). Everything here ran
without LocalStack and without a network. Where moto and the real range differ it is said.

1. **Purple twin: one escalation, one standing admin.** Actual: `intern` escalates in one hop via ESC-01 (`iam:CreatePolicyVersion` on
   `intern-policy`), `dev-svc` is admin, nothing else. Right.
2. **Hardened twin: zero escalation, no standing admin.** Actual: 0 and 0. `dev-svc`, `intern` and `aegis-deployer` are ordinary, and
   the break-glass role is listed as an expected admin. Right. What made me trust it: three deliberate breakages of the evaluator
   (ignore the boundary, ignore explicit Deny, accept any trust policy) each failed 2 to 6 tests. moto cannot store a permission
   boundary on a *user*, so the user boundary on this twin is set on the collected snapshot, not through the API (see
   `sentinel/tests/twins.py`). Roles are real.
3. **At least 99% fewer actions for `dev-svc`, at least 50% for `intern`.** Actual: 99.98% (19,521 to 3) and 75.0% (4 to 1). Right,
   and the first run was wrong in an instructive way: it said 3 granted and 100% for `intern`. Cause: IAM calls it
   `s3:ListAllMyBuckets`, botocore calls the operation `ListBuckets`, so the universe did not contain the action and the policy
   looked like it granted nothing. Fixed by adding the IAM names that differ, and pinned by a test against the real s3 model. My unit
   tests had used a hand-made universe that happened to contain the name, so they could not see it.
4. **Coverage 100% and the `intern` path gone.** Actual: complete for both (3 and 1 observed call-resource pairs checked), `intern`
   escalates to ordinary, `dev-svc` admin to ordinary. Right.
5. **Attack calls are left out.** Actual: `iam:CreateAccessKey` and `cloudtrail:StopLogging` reported as sensitive and not in the policy;
   `sts:GetCallerIdentity` listed as needing no permission. Right.
6. **Contain only for rules a playbook covers.** Actual (6 events through the real engine): `AEG-CRED-001` and `AEG-EXFIL-002` get
   `contain_via_playbook`; `AEG-EVAS-001`, `AEG-PERS-001`, `AEG-IMPACT-001`, `AEG-IMPACT-002` get `escalate_to_human`. Right.
7. **Hostile text cannot change a decision.** Actual: decisions identical for clean and hostile input in all 6 events, and none of the
   planted strings reached the note. Right for the template. My first version of this test was too weak: the hostile string
   contained a `/`, so identity extraction discarded it before it reached the code under test, and three deliberate breakages of the
   sanitiser still passed. After fixing the test (a hostile name without a `/`), each of those breakages fails at least one test.
   The model path is tested with a fake model only.
8. **A broken model never blocks.** Actual: 9 kinds of bad reply (not JSON, extra key, credential id, mention, link, emoji code, too long,
   too many items, markup) and 3 kinds of error (timeout, generic error, connection) all fall back to the template, with the reason in
   the note. Right.
9. **The first live scan breaks something small.** Not settled: no live run yet. Offline, against moto, two gaps of exactly this kind
   did appear and are handled: `get_account_authorization_details` omits `PolicyName` (a `KeyError` in the first version), and
   it omits the permission boundary on users (the collector now confirms every principal's boundary with `get_user` / `get_role`,
   because a dropped boundary overstates risk). LocalStack may have others.
10. **Under 5 ms with the model off, plan unchanged.** Actual: median 1.4 ms, p95 1.8 ms over 300 runs (LangGraph engine). The plan shown
    to the approver is the plan on the audit trail plus the advisory lines at the end; the only new audit record is `advice`.
    Right. Not measured: the cost of a live model call (bounded by a 3 s timeout, not predicted).

Not done in Stage 6: a live `make sentinel-scan` on LocalStack, a live model run, and any measurement of whether the note helps a
person decide faster.


---

## Predicted vs actual, live on LocalStack (2026-11-08; console output pasted by the owner, `docs/evidence/sentinel-live.md`)

1. **Purple twin: one escalation, one standing admin.** Actual on LocalStack: `intern` escalates by ESC-01 (`iam:CreatePolicyVersion` on
   `intern-policy`), `dev-svc` is admin, nothing else. Right, and the same as on moto.
2. **Hardened twin: zero and zero.** Actual: 0 and 0 (5 ordinary principals and the break-glass role as an expected admin). Right.
   The other four accounts also had no unexpected admin.
9. **The first live scan breaks something small.** Actual: it did not. All six accounts were collected and scanned, with 0 unresolved
   policies in every one, so neither of my first two guesses (AWS-managed documents missing, unmodelled principals) happened.
   Wrong. The two gaps found earlier were moto's, not LocalStack's. What did go wrong was outside the analysis: the `make`
   targets set an access key but no secret and relied on `source scripts/env.sh`, which stopped the first attempt before any
   IAM call. Fixed (the targets now set it themselves).

Not settled live: items 3 to 5 need a trail with activity from the principal. The first `make sentinel-leastpriv` ran before any
attack and reported `no usable events for dev-svc; seen: nobody`. That is expected for a principal that has not acted, but it is
not yet confirmed that LocalStack's `lookup_events` carries the caller at all (the Stage 2 finding that every caller looks the same
makes that a real risk). Items 6 to 8 and 10 on a real finding are also open.


---

## Predicted vs actual, triage inside a real approval (2026-11-08; prompt output pasted by the owner, `docs/evidence/triage-live.md`)

6. **Contain only for rules a playbook covers.** Actual on a real finding (`AEG-CRED-001`, medium): proposal `contain_via_playbook`, playbook
   `leaked_key`, priority P3. Right.
10. **The plan is unchanged and the advice comes after it.** Actual: the prompt showed the two plan steps first and then the four
    `[triage ...]` lines. Right. The prompt printed the advice as bullets beside the plan steps, which blurs what is advice. Fixed afterwards:
    advice now appears under its own heading, in the prompt, the pending list, the dry-run text and the Slack message.
* **Sentinel feeds triage.** The evidence line read `IAM exposure: admin`, taken from `build/sentinel/scan.json` for `dev-svc`. The link between
  the two Stage 6 parts works on real data, and the priority rose accordingly (the second reason in the note).
* **Not predicted, and the most useful result of the session:** the same approval ended with `CHAIN BROKEN` because two executing responders were
  running (ADR-0023). It was an existing Stage 4 hazard that the new live run exposed.

Still open: a live model, the n8n hand-off (not confirmed), `make sentinel-leastpriv` after real activity, items 7 and 8 on a real finding.


## Also observed live (2026-11-08)

* **Silence is a denial.** A second incident, after the ADR-0023 fix, was left unanswered for 120 s: `approval denied (timeout)`, `outcome timeout`, the key
  untouched, the chain intact, and exactly one record of each step (`docs/evidence/triage-live.md`). Not a Stage 6 prediction, but it is the
  advisory note's safety property: nothing the note says can cause an action.
* **Release flow (Stage 7), local key:** build, sign, verify pass; a one-byte change fails with `sha256 does not match`; a rebuild gives the same hash
  (`docs/evidence/release-local.md`).
