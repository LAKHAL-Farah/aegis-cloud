import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "detections"))

os.environ.setdefault("AEGIS_AUDIT_FSYNC", "0")        # tests do not need durable audit lines
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_DEFAULT_REGION="us-east-1")
for k in ("AWS_PROFILE", "AWS_ENDPOINT_URL"):
    os.environ.pop(k, None)

from aegis_detect.asff import to_asff  # noqa: E402
from aegis_detect.engine import Engine  # noqa: E402
from aegis_detect.model import Event  # noqa: E402

from aegis_respond.approval import Decision  # noqa: E402
from aegis_respond.audit import AuditLog  # noqa: E402,F401  (re-exported for conftest)
from aegis_respond.engine import Ledger, Responder  # noqa: E402,F401
from aegis_respond.policy import ResponsePolicy  # noqa: E402,F401

MOTO_ACCOUNT = "123456789012"
T0 = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)


def cloudtrail(name, service, *, who="dev-svc", acct=MOTO_ACCOUNT, at=0.0, req=None, key="AKIAEXAMPLEKEY0001", ua="Boto3/1.34 Botocore/1.34",
               principal_arn=None):
    arn = principal_arn or f"arn:aws:iam::{acct}:user/{who}"
    return {"eventVersion": "1.09", "eventTime": (T0 + timedelta(seconds=at)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": f"{service}.amazonaws.com", "eventName": name, "awsRegion": "us-east-1",
            "sourceIPAddress": "172.17.0.1", "userAgent": ua, "eventID": f"evt-{name}-{at}-{who}", "eventCategory": "Management",
            "recipientAccountId": acct, "requestParameters": req or {},
            "userIdentity": {"type": "IAMUser", "arn": arn, "accountId": acct, "userName": who, "accessKeyId": key}}


def findings_for(records, acct=MOTO_ACCOUNT, detected_after_s=2.0):
    """Run real CloudTrail-shaped records through the real detection engine and return ASFF findings."""
    dets = Engine().process([Event.from_cloudtrail(r, acct) for r in records])
    out = []
    for d in dets:
        d.detected_at = d.event_time + timedelta(seconds=detected_after_s)
        out.append(to_asff(d))
    return out


class Recorder:
    name = "recorder"

    def __init__(self):
        self.messages = []

    def send(self, text, payload=None):
        self.messages.append(text)


class Approve:
    name = "yes"

    def __init__(self, ok=True, by="tester", waited=0.0):
        self.ok, self.by, self.waited, self.calls = ok, by, waited, []

    def request(self, inc, plan, timeout_s):
        self.calls.append((inc, list(plan)))
        return Decision(self.ok, self.by if self.ok else (self.by), "test decision", waited_s=self.waited)


class FakeSlack:
    """A local stand-in for slack.com/api: stores messages and reactions, lets a test script who reacts."""

    def __init__(self):
        self.messages, self.replies, self.auth, self.calls = [], [], [], []
        self.on_post, self.fail_reactions, self.refuse = None, 0, None
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                from urllib.parse import parse_qs
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
                method = self.path.rsplit("/", 1)[-1]
                outer.auth.append(self.headers.get("Authorization"))
                outer.calls.append((method, form))
                if outer.refuse:
                    out = {"ok": False, "error": outer.refuse}
                elif method == "chat.postMessage" and "thread_ts" in form:
                    outer.replies.append(form)
                    out = {"ok": True, "channel": "C0TEST", "ts": "9.9"}
                elif method == "chat.postMessage":
                    ts = f"{len(outer.messages) + 1}.000100"
                    outer.messages.append({"ts": ts, "text": form.get("text", ""), "reactions": []})
                    if outer.on_post:
                        outer.on_post(ts)
                    out = {"ok": True, "channel": "C0TEST", "ts": ts}
                elif method == "reactions.get":
                    if outer.fail_reactions > 0:
                        outer.fail_reactions -= 1
                        out = {"ok": False, "error": "ratelimited"}
                    else:
                        msg = next((m for m in outer.messages if m["ts"] == form.get("timestamp")), None)
                        out = {"ok": True, "message": {"reactions": msg["reactions"]}} if msg else {"ok": False, "error": "message_not_found"}
                else:
                    out = {"ok": False, "error": "unknown_method"}
                payload = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def react(self, name, users, ts=None):
        msg = next(m for m in self.messages if ts is None or m["ts"] == ts) if ts else self.messages[-1]
        msg["reactions"].append({"name": name, "users": list(users), "count": len(users)})

    def close(self):
        self.httpd.shutdown()
