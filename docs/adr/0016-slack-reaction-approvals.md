# ADR-0016: Slack reactions replace Telegram as the chat approval channel

* Status: accepted (amends point 3 of ADR-0015)
* Date: 2026-11-04

## Context
ADR-0015 chose Telegram for human approval because long-polling needs no inbound port. The owner does not use Telegram
and does use Slack. Slack's native approval UI is buttons, but Slack delivers a button click to a public HTTPS URL
(or over Socket Mode, which needs a WebSocket client library). A laptop has no public URL, a tunnel is a second thing to
secure, and a new dependency is a second thing to trust.

## Decision
* Approval is a **reaction**. `SlackApprover` posts the plan to a channel with `chat.postMessage`, then polls
  `reactions.get` on that message: :white_check_mark: approves, :x: denies. Everything is an outbound HTTPS call, so
  nothing listens, and there is no new dependency (standard library only).
* Only reactions from the user ids in `SLACK_ALLOWED_USER_IDS` count, and only on **this request's message** (its
  timestamp is the nonce, so an old approval cannot approve a new request). There is no default allow list: with
  none configured the approver refuses to start. A deny from an allowed user beats an approve.
* Fail closed, as before: no reaction, a Slack error, a deleted message or an unreachable Slack all end as a denial.
  A rate limit while polling is retried until the deadline.
* The same bot token can post the notifications (`SlackBotNotifier`). The older incoming-webhook notifier remains as a
  notify-only fallback. n8n stays notify-only (ADR-0015).
* Telegram is removed (code, tests, docs) rather than left dormant: a channel nobody uses is attack surface nobody reviews.
* A terminal prompt (`respond.py prompt`) is added for the file approver, so a one-window demo needs no copied ids.

## Consequences
* (+) No public endpoint, no tunnel, no new package. The Slack protocol is tested against a local fake Web API.
* (+) The decision is visible in the channel, with who approved it, next to the plan.
* (-) **Not tested against real Slack by the author.** The tests use a fake server that follows Slack's documented
  response shapes. The first live run may surface a scope or channel-membership detail; the error text names it (for
  example `missing_scope`, `not_in_channel`).
* (-) Reactions are polled every 2 s, so an approval can be noticed up to 2 s late. That is inside `human_wait_s`,
  and `machine_s` excludes it.
* (-) Anyone in the channel can read the plan (principal, last four characters of a key id, bucket name). Use a private
  channel. Never put key material in a message: the playbooks do not.
* (-) A reaction is a weaker act than a button with a confirmation, but it is attributable (Slack records who reacted)
  and limited to the allow list.
