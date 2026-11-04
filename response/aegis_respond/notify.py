"""Where humans and other systems hear about an incident. A failed notification never blocks containment."""
from __future__ import annotations

import json
import urllib.request
from typing import Protocol

from .approval import SlackAPI


class Notifier(Protocol):
    name: str

    def send(self, text: str, payload: dict | None = None) -> None: ...


class StdoutNotifier:
    name = "stdout"

    def send(self, text: str, payload: dict | None = None) -> None:
        print(text, flush=True)


class SlackBotNotifier:
    """Posts to a channel with the same bot token the approver uses (chat:write scope)."""
    name = "slack"

    def __init__(self, api: SlackAPI, channel: str):
        self.api, self.channel = api, channel

    def send(self, text: str, payload: dict | None = None) -> None:
        self.api.call("chat.postMessage", {"channel": self.channel, "text": text})


class SlackNotifier:
    """Incoming-webhook notifications only (no bot token needed). Approval is SlackApprover's job."""
    name = "slack"

    def __init__(self, webhook_url: str):
        self.url = webhook_url

    def send(self, text: str, payload: dict | None = None) -> None:
        _post(self.url, {"text": text})


class WebhookNotifier:
    """POST the structured incident to a webhook, for example an n8n Webhook node that opens a ticket, enriches
    with threat intel or pages someone. It is fan-out only: whatever listens cannot trigger containment."""
    name = "webhook"

    def __init__(self, url: str, bearer: str | None = None):
        self.url, self.bearer = url, bearer

    def send(self, text: str, payload: dict | None = None) -> None:
        _post(self.url, {"text": text, **(payload or {})}, self.bearer)


def _post(url: str, body: dict, bearer: str | None = None) -> None:
    headers = {"Content-Type": "application/json", **({"Authorization": f"Bearer {bearer}"} if bearer else {})}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"POST failed: {type(exc).__name__}") from None     # never echo the URL (it can be a secret)


class Fanout:
    name = "fanout"

    def __init__(self, notifiers: list, on_error=None):
        self.notifiers, self.on_error = list(notifiers), on_error or (lambda n, e: None)

    def send(self, text: str, payload: dict | None = None) -> None:
        for n in self.notifiers:
            try:
                n.send(text, payload)
            except Exception as exc:  # noqa: BLE001
                self.on_error(n.name, str(exc))
