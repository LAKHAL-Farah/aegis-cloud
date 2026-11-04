# Response playbooks (Stage 4)

```
detector (Stage 3)              responder (Stage 4)                                  people / systems
CloudTrail -> rules -> ASFF  -> build/findings/*.json
                                 match playbook by rule id   (response/policy.json)
                                 protected identity?  yes -> refuse, tell a human
                                 plan (READ-ONLY): what exists, what would change
                                 ask  --------------------------------------------> Telegram [Approve][Deny]  or  file
                                 <-------------------------------------------------- decision (timeout = deny)
                                 contain -> verify (read back)
                                 audit trail (hash chain) + notify ------------------> Telegram, Slack, n8n webhook
```

| Playbook | Listens for (rule) | Plan and containment | Verify | Rollback |
| --- | --- | --- | --- | --- |
| `leaked_key` | `AEG-ACCESS-001`, `AEG-CRED-001`, `AEG-EXFIL-003` | Deactivate the access key named in the log (or every active key of that IAM user when the log's key id is not the user's), then create one replacement key and store it in Secrets Manager under `aegis/rotated-access-key/<account>/<user>` | Every targeted key reads back `Inactive` | `respond.py rollback <id>` re-activates the keys |
| `public_bucket` | `AEG-EXFIL-002` | Turn all four Block Public Access settings on, reset a public ACL to private | BPA fully on and no AllUsers/AuthenticatedUsers grant | none by design |

Refusals, each explained to the human: root, protected names, role sessions (nothing to deactivate), users of another
account, a user or bucket that no longer exists, a bucket the finding does not name.

## Run it

```bash
make response-install && make response-test          # no LocalStack needed
make respond-plan                                      # dry run: plans, changes nothing
make respond-up APPROVER=file                          # acts after approval
make respond-pending                                   # what is waiting
make respond-approve ID=<incident id>                  # or respond-deny
make respond-audit                                     # trail + chain check
make respond-rollback ID=<incident id>
```

Telegram (the demo): create a bot with BotFather, then

```bash
export TELEGRAM_BOT_TOKEN=...        # never commit it
export TELEGRAM_CHAT_ID=...          # your chat
export TELEGRAM_ALLOWED_USER_IDS=... # comma separated; defaults to the chat id (fine for a private chat)
make respond-up APPROVER=telegram
```

Optional fan-out: `SLACK_WEBHOOK_URL`, and `AEGIS_WEBHOOK_URL` (+ `AEGIS_WEBHOOK_BEARER`) for an n8n Webhook node. n8n receives
`{text, incident_id, rule, technique, severity, account_id, principal, resource, title}`. It never receives key material.

## Measured run

```bash
make stage4-run LABEL=stage4-v1                        # simulated approval (measures the machines)
make stage4-run LABEL=stage4-v2 APPROVER=telegram      # a person taps Approve (measures the whole loop)
```

It writes `docs/evidence/scorecards/<label>.{json,md}` with attack-to-contained time, the approval wait and the machine
time separately, and checks the final state with its own admin client. Write `docs/stage4-predictions.md` first.

## Real AWS (not exercised here)

Run `respond.py watch --execute --approver telegram` with no `--endpoint` under a role that can `iam:ListAccessKeys`,
`iam:UpdateAccessKey`, `iam:CreateAccessKey`, `iam:DeleteAccessKey` (orphan cleanup only), `secretsmanager:CreateSecret|PutSecretValue`,
`s3:Get/PutPublicAccessBlock`, `s3:Get/PutBucketAcl`. Or deploy `make lambda-package` behind an EventBridge rule on the
`aegis-findings` bus, with `AEG_APPROVAL_HMAC_KEY` set and an approval step that signs with `approval.sign_approval`.
Auto-approval is refused outside LocalStack.

## Known limits

* On LocalStack the access key id in CloudTrail is the account id, so `leaked_key` takes the "all active keys of that user" path.
* LocalStack may not enforce an `Inactive` key on later API calls. The scorecard therefore verifies the key's state, and does not claim a blocked request.
* Findings are consumed from files. Whether EventBridge on LocalStack delivers to the Lambda has not been tested.
* The first approval wait is the only human-dependent number. A "90 seconds" claim needs the Telegram run, not the simulated one.
