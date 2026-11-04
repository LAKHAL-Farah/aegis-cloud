"""Build notifiers and approvers from the environment. Secrets are read here and nowhere else."""
from __future__ import annotations

import os
from pathlib import Path

from .approval import AutoApprover, FileApprover, TelegramAPI, TelegramApprover
from .notify import Fanout, SlackNotifier, StdoutNotifier, TelegramNotifier, WebhookNotifier


def telegram_api(env=os.environ) -> TelegramAPI | None:
    return TelegramAPI(env["TELEGRAM_BOT_TOKEN"], env.get("TELEGRAM_API_BASE", "https://api.telegram.org")) \
        if env.get("TELEGRAM_BOT_TOKEN") else None


def build_notifier(env=os.environ, on_error=None) -> Fanout:
    parts = [StdoutNotifier()]
    api = telegram_api(env)
    if api and env.get("TELEGRAM_CHAT_ID"):
        parts.append(TelegramNotifier(api, env["TELEGRAM_CHAT_ID"]))
    if env.get("SLACK_WEBHOOK_URL"):
        parts.append(SlackNotifier(env["SLACK_WEBHOOK_URL"]))
    if env.get("AEGIS_WEBHOOK_URL"):
        parts.append(WebhookNotifier(env["AEGIS_WEBHOOK_URL"], env.get("AEGIS_WEBHOOK_BEARER")))
    return Fanout(parts, on_error)


def build_approver(kind: str, state_dir: Path, env=os.environ, auto_delay_s: float = 0.0):
    if kind == "auto":
        return AutoApprover(delay_s=auto_delay_s)
    if kind == "file":
        return FileApprover(Path(state_dir) / "approvals")
    if kind == "telegram":
        api = telegram_api(env)
        chat = env.get("TELEGRAM_CHAT_ID")
        if not api or not chat:
            raise SystemExit("telegram approver needs TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
        allowed = [int(x) for x in env.get("TELEGRAM_ALLOWED_USER_IDS", chat).split(",") if x.strip().lstrip("-").isdigit()]
        return TelegramApprover(api, chat, allowed)
    raise SystemExit(f"unknown approver {kind!r}")
