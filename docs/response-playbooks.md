# Response playbooks (Stage 4)

```
detector (Stage 3)              responder (Stage 4)                                  people / systems
CloudTrail -> rules -> ASFF  -> build/findings/*.json
                                 match playbook by rule id   (response/policy.json)
                                 protected identity?  yes -> refuse, tell a human
                                 plan (READ-ONLY): what exists, what would change
                                 ask  --------------------------------------------> Slack (react :white_check_mark: / :x:)  or  terminal prompt
                                 <-------------------------------------------------- decision (allow-listed person; timeout = deny)
                                 contain -> verify (read back)
                                 audit trail (hash chain) + notify ------------------> Slack, n8n webhook
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
make respond-prompt                                    # answer approvals here with y/N (one window)
make respond-pending                                   # or: see what is waiting ...
make respond-approve ID=<incident id>                  # ... and answer from another terminal (respond-deny to refuse)
make respond-audit                                     # trail + chain check
make respond-rollback ID=<incident id>
```

Slack approval (reactions, no public URL, no extra package):

1. https://api.slack.com/apps -> Create New App -> From scratch -> name it `AegisCloud`, pick your workspace.
2. OAuth & Permissions -> Bot Token Scopes: `chat:write` and `reactions:read`. (If Slack answers `missing_scope`, also add
   `channels:history` for a public channel or `groups:history` for a private one.)
3. Install to Workspace, copy the **Bot User OAuth Token** (`xoxb-...`).
4. Make a private channel, e.g. `#aegis-alerts`, and invite the bot: `/invite @AegisCloud`.
5. Copy the channel id (channel details, bottom) and your member id (your profile, three dots, Copy member ID, `U...`).
6. Put them in `.env` (gitignored, never commit) and load them in the terminal that starts the responder:

```bash
cat >> .env <<'EOF'
SLACK_BOT_TOKEN=xoxb-...
SLACK_CHANNEL=C0123456789
SLACK_ALLOWED_USER_IDS=U0123456789      # comma separated; REQUIRED, there is no default
EOF
set -a; source .env; set +a
curl -s -H "Authorization: Bearer $SLACK_BOT_TOKEN" https://slack.com/api/auth.test     # "ok":true
make respond-up APPROVER=slack
```

The bot posts the plan; react :white_check_mark: to approve or :x: to deny within the timeout (120 s). Reactions from anyone not in
`SLACK_ALLOWED_USER_IDS` are ignored. Notifications use the same token and channel.

Optional fan-out: `SLACK_WEBHOOK_URL` (notify-only, used when there is no bot token), and `AEGIS_WEBHOOK_URL` (+ `AEGIS_WEBHOOK_BEARER`) for an n8n Webhook node. n8n receives
`{text, incident_id, rule, technique, severity, account_id, principal, resource, title}`. It never receives key material.

## Measured run

```bash
make stage4-run LABEL=stage4-v1                        # simulated approval (measures the machines)
make stage4-run LABEL=stage4-v2 MEASURE_APPROVER=slack  # a person reacts in Slack (measures the whole loop)
make stage4-run LABEL=stage4-v3 MEASURE_APPROVER=file   # a person answers at the terminal: in a second window run
#   make respond-prompt STATE=build/response/measure-stage4-v3
```

It writes `docs/evidence/scorecards/<label>.{json,md}` with attack-to-contained time, the approval wait and the machine
time separately, and checks the final state with its own admin client. Write `docs/stage4-predictions.md` first.

## Real AWS (not exercised here)

Run `respond.py watch --execute --approver slack` with no `--endpoint` under a role that can `iam:ListAccessKeys`,
`iam:UpdateAccessKey`, `iam:CreateAccessKey`, `iam:DeleteAccessKey` (orphan cleanup only), `secretsmanager:CreateSecret|PutSecretValue`,
`s3:Get/PutPublicAccessBlock`, `s3:Get/PutBucketAcl`. Or deploy `make lambda-package` behind an EventBridge rule on the
`aegis-findings` bus, with `AEG_APPROVAL_HMAC_KEY` set and an approval step that signs with `approval.sign_approval`.
Auto-approval is refused outside LocalStack.

## Known limits

* On LocalStack the access key id in CloudTrail is the account id, so `leaked_key` takes the "all active keys of that user" path.
* LocalStack may not enforce an `Inactive` key on later API calls. The scorecard therefore verifies the key's state, and does not claim a blocked request.
* Findings are consumed from files. Whether EventBridge on LocalStack delivers to the Lambda has not been tested.
* The first approval wait is the only human-dependent number. A "90 seconds" claim needs a Slack or terminal run, not the simulated one.
* The Slack approver is tested against a local fake of Slack's Web API, not against slack.com.
