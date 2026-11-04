"""Build notifiers and approvers from the environment. Secrets are read here and nowhere else."""
from __future__ import annotations

import os
from pathlib import Path

from .approval import AutoApprover, FileApprover, SlackAPI, SlackApprover
from .notify import Fanout, SlackBotNotifier, SlackNotifier, StdoutNotifier, WebhookNotifier


def slack_api(env=os.environ) -> SlackAPI | None:
    return SlackAPI(env["SLACK_BOT_TOKEN"], env.get("SLACK_API_BASE", "https://slack.com/api")) if env.get("SLACK_BOT_TOKEN") else None


def build_notifier(env=os.environ, on_error=None) -> Fanout:
    parts = [StdoutNotifier()]
    api = slack_api(env)
    if api and env.get("SLACK_CHANNEL"):
        parts.append(SlackBotNotifier(api, env["SLACK_CHANNEL"]))
    elif env.get("SLACK_WEBHOOK_URL"):
        parts.append(SlackNotifier(env["SLACK_WEBHOOK_URL"]))
    if env.get("AEGIS_WEBHOOK_URL"):
        parts.append(WebhookNotifier(env["AEGIS_WEBHOOK_URL"], env.get("AEGIS_WEBHOOK_BEARER")))
    return Fanout(parts, on_error)


def build_approver(kind: str, state_dir: Path, env=os.environ, auto_delay_s: float = 0.0):
    if kind == "auto":
        return AutoApprover(delay_s=auto_delay_s)
    if kind == "file":
        return FileApprover(Path(state_dir) / "approvals")
    if kind == "slack":
        api = slack_api(env)
        missing = [k for k in ("SLACK_BOT_TOKEN", "SLACK_CHANNEL", "SLACK_ALLOWED_USER_IDS") if not env.get(k)]
        if missing:
            raise SystemExit("slack approver needs " + ", ".join(missing) + " (see docs/response-playbooks.md)")
        return SlackApprover(api, env["SLACK_CHANNEL"], env["SLACK_ALLOWED_USER_IDS"].split(","))
    raise SystemExit(f"unknown approver {kind!r}")
