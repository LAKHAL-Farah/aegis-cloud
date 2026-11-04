"""Human approval gates. Every gate FAILS CLOSED: a timeout, an error or an unknown reply is a denial."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
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


class SlackAPI:
    """The few Slack Web API calls we use, over urllib (form-encoded, bearer token). `base` is overridable for tests.
    The token lives only in this object's header and is never put in an error message."""

    def __init__(self, token: str, base: str = "https://slack.com/api"):
        self.base, self._auth = base.rstrip("/"), f"Bearer {token}"

    def __repr__(self) -> str:
        return f"SlackAPI(base={self.base!r})"

    def call(self, method: str, params: dict | None = None, timeout: float = 15) -> dict:
        req = urllib.request.Request(
            f"{self.base}/{method}", data=urllib.parse.urlencode(params or {}).encode(), method="POST",
            headers={"Authorization": self._auth, "Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"slack {method} failed: HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise RuntimeError(f"slack {method} failed: {type(exc).__name__}") from None
        if not data.get("ok"):
            raise RuntimeError(f"slack {method} refused: {data.get('error', 'unknown')}")
        return data


APPROVE_REACTIONS = {"white_check_mark", "heavy_check_mark"}
DENY_REACTIONS = {"x", "no_entry", "no_entry_sign"}


class SlackApprover:
    """Posts the plan to a channel and waits for an allow-listed person to react with a check mark (approve) or an X (deny).

    Why reactions and not buttons: Slack delivers button clicks to a public URL, which a laptop does not have and
    which would be a second control path to defend. A reaction is read by polling Slack outward, so nothing listens.

    Safety: only reactions from the allow-listed user ids count, and only on THIS request's message (its timestamp is
    the nonce). A deny from an allowed user beats an approve. Silence, errors and an unreachable Slack are a denial."""
    name = "slack"

    def __init__(self, api: SlackAPI, channel: str, allowed_user_ids: list[str], poll_s: float = 2.0,
                 now=time.monotonic, sleep=time.sleep):
        allowed = {str(u).strip() for u in allowed_user_ids if str(u).strip()}
        if not allowed:
            raise ValueError("SlackApprover needs at least one allowed Slack user id (looks like U01234ABCDE)")
        self.api, self.channel, self.allowed, self.poll_s, self._now, self._sleep = api, channel, allowed, poll_s, now, sleep

    def _say(self, chan: str, ts: str, text: str) -> None:
        try:
            self.api.call("chat.postMessage", {"channel": chan, "thread_ts": ts, "text": text})
        except RuntimeError:
            pass                                    # a failed follow-up never changes the decision

    def request(self, inc: Incident, plan: list[str], timeout_s: float) -> Decision:
        who = ", ".join(f"<@{u}>" for u in sorted(self.allowed))
        text = (f":rotating_light: *AegisCloud {inc.severity.upper()}*: {inc.title}\nPrincipal: `{inc.principal}`   "
                f"Technique: {inc.technique}   Rule: {inc.rule}\n\n*Planned actions*\n" + "\n".join(f"- {p}" for p in plan) +
                f"\n\n{who}: react :white_check_mark: to approve or :x: to deny within {timeout_s:.0f} s. Otherwise nothing happens.")
        sent = self.api.call("chat.postMessage", {"channel": self.channel, "text": text})
        chan, ts = sent.get("channel", self.channel), sent["ts"]
        start = self._now()
        while True:
            try:
                msg = self.api.call("reactions.get", {"channel": chan, "timestamp": ts, "full": "true"}).get("message", {})
            except RuntimeError:
                msg = {}                            # a hiccup (rate limit, 5xx): try again until the deadline
            votes: dict[str, set] = {"approve": set(), "deny": set()}
            for r in msg.get("reactions", []):
                name = str(r.get("name", "")).split("::")[0]          # "+1::skin-tone-2" style suffixes
                users = {u for u in r.get("users", []) if u in self.allowed}
                if name in APPROVE_REACTIONS:
                    votes["approve"] |= users
                elif name in DENY_REACTIONS:
                    votes["deny"] |= users
            waited = self._now() - start
            if votes["deny"]:
                u = sorted(votes["deny"])[0]
                self._say(chan, ts, f"Denied by <@{u}>. No action taken.")
                return Decision(False, f"slack:{u}", "denied in Slack", waited_s=waited)
            if votes["approve"]:
                u = sorted(votes["approve"])[0]
                self._say(chan, ts, f"Approved by <@{u}>. Containing now.")
                return Decision(True, f"slack:{u}", "approved in Slack", waited_s=waited)
            if waited >= timeout_s:
                self._say(chan, ts, f"No decision within {timeout_s:.0f} s. No action taken.")
                return Decision(False, "timeout", f"no reaction within {timeout_s:.0f} s", waited_s=waited)
            self._sleep(max(0.0, min(self.poll_s, timeout_s - waited)))


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
