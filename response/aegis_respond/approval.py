"""Human approval gates. Every gate FAILS CLOSED: a timeout, an error or an unknown reply is a denial."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .incident import Incident


@dataclass
class Decision:
    approved: bool
    by: str
    reason: str
    automated: bool = False
    waited_s: float = 0.0


class AutoApprover:
    """Approves without asking. For measured runs on LocalStack only: the engine refuses to build it against
    anything else, and the scorecard labels the run 'simulated approval'."""
    name = "auto"

    def __init__(self, delay_s: float = 0.0, sleep=time.sleep):
        self.delay_s, self._sleep = delay_s, sleep

    def request(self, inc: Incident, plan: list[str], timeout_s: float) -> Decision:
        self._sleep(self.delay_s)
        return Decision(True, "auto-approver", "simulated approval (LocalStack measured run)", automated=True,
                        waited_s=self.delay_s)


class FileApprover:
    """Writes <dir>/<id>.request.json, then waits for <dir>/<id>.decision containing `approve <name>` or `deny <name>`.
    `respond.py approve <id>` writes that file. Zero network, so it works in CI and on a plane."""
    name = "file"

    def __init__(self, directory: Path, poll_s: float = 0.25, now=time.monotonic, sleep=time.sleep):
        self.dir, self.poll_s, self._now, self._sleep = Path(directory), poll_s, now, sleep

    def request(self, inc: Incident, plan: list[str], timeout_s: float) -> Decision:
        self.dir.mkdir(parents=True, exist_ok=True)
        req, dec = self.dir / f"{inc.short}.request.json", self.dir / f"{inc.short}.decision"
        dec.unlink(missing_ok=True)
        tmp = req.with_suffix(".tmp")           # write-then-rename: a reader never sees a half-written request
        tmp.write_text(json.dumps({**inc.public(), "plan": plan, "expires_in_s": timeout_s}, indent=2))
        os.replace(tmp, req)
        start = self._now()
        while self._now() - start < timeout_s:
            if dec.exists():
                word, _, who = dec.read_text().strip().partition(" ")
                req.unlink(missing_ok=True)
                dec.unlink(missing_ok=True)
                ok = word.lower() == "approve"
                return Decision(ok, who or "unknown", "approved by file" if ok else "denied by file",
                                waited_s=self._now() - start)
            self._sleep(self.poll_s)
        req.unlink(missing_ok=True)
        return Decision(False, "timeout", f"no decision within {timeout_s:.0f} s", waited_s=self._now() - start)

    @staticmethod
    def pending(directory: Path) -> list[dict]:
        out = []
        for p in sorted(Path(directory).glob("*.request.json")):
            try:
                out.append(json.loads(p.read_text()))
            except (OSError, ValueError):      # being replaced or removed right now: skip it this time
                continue
        return out

    @staticmethod
    def decide(directory: Path, incident_short: str, approve: bool, who: str) -> Path:
        directory = Path(directory)
        if not (directory / f"{incident_short}.request.json").exists():
            raise FileNotFoundError(f"no pending approval {incident_short}")
        path = directory / f"{incident_short}.decision"
        path.write_text(f"{'approve' if approve else 'deny'} {who}")
        return path


class TelegramAPI:
    """Just the four Bot API calls we use, over urllib. `base` is overridable so tests can use a local server."""

    def __init__(self, token: str, base: str = "https://api.telegram.org"):
        self._url = f"{base.rstrip('/')}/bot{token}"      # the token lives only here and is never logged

    def call(self, method: str, payload: dict | None = None, timeout: float = 15) -> dict:
        req = urllib.request.Request(f"{self._url}/{method}", data=json.dumps(payload or {}).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError(f"telegram {method} failed: {type(exc).__name__}") from None   # no URL, so no token
        if not data.get("ok"):
            raise RuntimeError(f"telegram {method} refused: {data.get('description', 'unknown')}")
        return data


class TelegramApprover:
    """Sends the plan with Approve / Deny buttons and long-polls for the tap (no inbound port, works behind NAT).

    A tap counts only if the callback carries this request's nonce AND comes from an allow-listed user id.
    Stale buttons from an earlier request therefore cannot approve a later one."""
    name = "telegram"

    def __init__(self, api: TelegramAPI, chat_id: int | str, allowed_user_ids: list[int], poll_s: int = 5,
                 now=time.monotonic):
        if not allowed_user_ids:
            raise ValueError("TelegramApprover needs at least one allowed user id")
        self.api, self.chat_id, self.allowed, self.poll_s, self._now = api, chat_id, {int(u) for u in allowed_user_ids}, poll_s, now

    def _offset(self) -> int:
        updates = self.api.call("getUpdates", {"timeout": 0}).get("result", [])
        return (updates[-1]["update_id"] + 1) if updates else 0

    def request(self, inc: Incident, plan: list[str], timeout_s: float) -> Decision:
        offset = self._offset()                       # ignore everything tapped before this request existed
        nonce = secrets.token_hex(4)
        text = (f"AegisCloud {inc.severity.upper()}: {inc.title}\nPrincipal: {inc.principal}\n"
                f"Technique: {inc.technique}  Rule: {inc.rule}\n\nPlanned actions:\n" + "\n".join(f"- {p}" for p in plan) +
                f"\n\nApprove within {timeout_s:.0f} s, or nothing happens.")
        sent = self.api.call("sendMessage", {"chat_id": self.chat_id, "text": text, "reply_markup": {"inline_keyboard": [[
            {"text": "Approve", "callback_data": f"aegis:{inc.short}:{nonce}:y"},
            {"text": "Deny", "callback_data": f"aegis:{inc.short}:{nonce}:n"}]]}})
        message_id = sent["result"]["message_id"]
        start = self._now()
        while (left := timeout_s - (self._now() - start)) > 0:
            batch = self.api.call("getUpdates", {"offset": offset, "timeout": int(max(1, min(self.poll_s, left)))},
                                  timeout=self.poll_s + 10).get("result", [])
            for upd in batch:
                offset = upd["update_id"] + 1
                cb = upd.get("callback_query")
                if not cb or not str(cb.get("data", "")).startswith(f"aegis:{inc.short}:{nonce}:"):
                    continue
                who = cb.get("from") or {}
                self.api.call("answerCallbackQuery", {"callback_query_id": cb["id"]})
                if int(who.get("id", 0)) not in self.allowed:
                    continue                           # a stranger tapped the button: ignore, keep waiting
                ok = cb["data"].endswith(":y")
                self.api.call("editMessageReplyMarkup", {"chat_id": self.chat_id, "message_id": message_id,
                                                         "reply_markup": {"inline_keyboard": []}})
                return Decision(ok, f"telegram:{who.get('username') or who.get('id')}",
                                "approved in Telegram" if ok else "denied in Telegram", waited_s=self._now() - start)
        return Decision(False, "timeout", f"no tap within {timeout_s:.0f} s", waited_s=self._now() - start)


# ---- signed approvals, for the Lambda path where the approval happened somewhere else (n8n, a person, a state machine)

def sign_approval(key: bytes, incident_id: str, approved_by: str, expires_epoch: int) -> str:
    return hmac.new(key, f"{incident_id}|{approved_by}|{expires_epoch}".encode(), hashlib.sha256).hexdigest()


def verify_approval(key: bytes, incident_id: str, approval: dict | None, now: float | None = None) -> Decision:
    """An approval carried inside an event is only believed if it is signed for THIS incident and not expired."""
    if not key:
        return Decision(False, "none", "no approval key configured")
    if not isinstance(approval, dict):
        return Decision(False, "none", "no approval in the event")
    try:
        by, exp, sig = str(approval["approved_by"]), int(approval["expires"]), str(approval["signature"])
    except (KeyError, ValueError, TypeError):
        return Decision(False, "none", "malformed approval")
    if (now if now is not None else time.time()) > exp:
        return Decision(False, by, "approval expired")
    if not hmac.compare_digest(sig, sign_approval(key, incident_id, by, exp)):
        return Decision(False, by, "approval signature does not match this incident")
    return Decision(True, by, "signed approval verified")
