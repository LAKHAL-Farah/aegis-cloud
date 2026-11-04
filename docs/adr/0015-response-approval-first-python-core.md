# ADR-0015: Response is approval-first, with a Python core and n8n as a consumer

* Status: accepted
* Date: 2026-11-04

## Context
Stage 4 needs finding -> approve -> contain -> verify, measured, demoable in 90 seconds, and runnable with no AWS
account. The plan names n8n, Lambda, SSM, Telegram or Slack, and an audit trail. ADR-0005 already decided that
triggers come from our own detections, not from Config.

## Decision
1. **One Python core (`response/aegis_respond`) does the work.** The same `Responder` runs from a directory
   watcher (LocalStack demo), from the CLI, and from a Lambda handler (EventBridge, real AWS).
2. **A human approves before anything changes, and silence means no.** Approval timeout, a crashing channel, an
   unknown reply and an unsigned event are all denials. `plan()` is read-only. `contain()` receives the exact
   plan the human saw.
3. **Telegram approves, Slack and n8n are told.** Telegram long-polling needs no inbound port and checks the
   tapper's user id against an allow list and a per-request nonce. Slack buttons and n8n callbacks need a public
   endpoint, which would be a second control path to defend, so Slack (webhook) and n8n (Webhook node) are
   notified only. n8n can enrich, open tickets and page people. It cannot trigger containment.
4. **The Lambda path accepts only signed approvals.** `approval = HMAC(key, finding id | approver | expiry)`.
   Whoever can put events on the bus can forge an unsigned approval, so the signature carries the authority.
5. **Containment is reversible and minimal.** Keys are deactivated, never deleted. Public buckets get Block
   Public Access back, never a policy rewrite. Rollback of a key is one command. Rollback of a bucket is never
   automatic, because re-publishing is a human decision.
6. **Never touch** `root`, `break-glass-*`, `aegis-*` (policy), roles, or another account's users. The playbook
   explains the refusal to the human instead.
7. **The audit trail is a hash chain** (tamper-evident, `respond.py audit` verifies it) and never holds key material.
8. **`AutoApprover` exists for the measured run only.** It is refused unless the endpoint is LocalStack, and the
   scorecard says "simulated approval".
9. **The responder obeys ADR-0013.** `test_not_rigged.py` fails the build if response code or its policy names a
   scenario, a run id, the range's accounts or its identities. Playbooks are chosen by detection rule id in `policy.json`.

## Consequences
* (+) Everything except the live LocalStack calls is tested in CI with moto and a fake Bot API, no network.
* (+) Real AWS needs no new logic: set the endpoint to none, use a role, run the Lambda.
* (-) n8n shows up as a webhook consumer, not an orchestrator. A workflow that approves inside n8n is a later option.
* (-) SSM Automation (instance quarantine, snapshot) and Terraform for the Lambda and bus rule are not in this change.
* (-) The ledger is a local file. On Lambda it lives in /tmp, so a cold start can forget a recent incident. Use DynamoDB if that matters.
* (-) Rotation stores a new long-lived key in Secrets Manager. On real AWS prefer roles or OIDC and rotate only what cannot move.
