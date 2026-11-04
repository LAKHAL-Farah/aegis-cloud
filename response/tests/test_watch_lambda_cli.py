import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from aegis_respond import lambda_handler
from aegis_respond.approval import sign_approval
from aegis_respond.clients import Clients
from aegis_respond.watch import watch
from rsupport import MOTO_ACCOUNT, cloudtrail, findings_for
from moto import mock_aws

ROOT = Path(__file__).resolve().parents[1]


class StubResponder:
    def __init__(self):
        self.handled = []
        self.audit = type("A", (), {"append": lambda *a, **k: None})()

    def handle(self, finding):
        self.handled.append(finding["n"])
        return type("O", (), {"status": "X", "detail": ""})()


def run_watch(tmp_path, **kw):
    stop, resp = threading.Event(), StubResponder()
    t = threading.Thread(target=watch, args=(resp, tmp_path, stop), kwargs={"poll_s": 0.02, **kw})
    t.start()
    time.sleep(0.15)          # let the watcher take its startup snapshot of what is already on disk
    return stop, resp, t


def drop(path, name, n):
    (path / name).write_text(json.dumps({"n": n}))


def settle(resp, count, secs=3):
    end = time.time() + secs
    while len(resp.handled) < count and time.time() < end:
        time.sleep(0.02)


def test_watch_handles_new_findings_but_not_the_old_ones(tmp_path):
    drop(tmp_path, "old.json", "old")
    stop, resp, t = run_watch(tmp_path)
    drop(tmp_path, "new.json", "new")
    settle(resp, 1)
    stop.set(); t.join(5)
    assert resp.handled == ["new"]


def test_watch_replay_handles_everything_once(tmp_path):
    drop(tmp_path, "a.json", "a"); drop(tmp_path, "b.json", "b")
    stop, resp, t = run_watch(tmp_path, replay=True)
    settle(resp, 2); time.sleep(0.2)
    stop.set(); t.join(5)
    assert sorted(resp.handled) == ["a", "b"]


def test_watch_since_skips_files_older_than_the_cutoff(tmp_path):
    drop(tmp_path, "old.json", "old")
    os.utime(tmp_path / "old.json", (time.time() - 100, time.time() - 100))
    stop, resp, t = run_watch(tmp_path, since=time.time() - 10)
    drop(tmp_path, "fresh.json", "fresh")
    settle(resp, 1)
    stop.set(); t.join(5)
    assert resp.handled == ["fresh"]


def test_a_broken_file_does_not_kill_the_watcher(tmp_path):
    stop, resp, t = run_watch(tmp_path)
    (tmp_path / "bad.json").write_text("{not json")
    drop(tmp_path, "good.json", "good")
    settle(resp, 1)
    stop.set(); t.join(5)
    assert resp.handled == ["good"]


# ---- Lambda
KEY = "lambda-hmac-key-0123456789abcdef"


@pytest.fixture
def lam(tmp_path, monkeypatch):
    monkeypatch.setattr(lambda_handler, "STATE", tmp_path)
    monkeypatch.setenv("AEG_APPROVAL_HMAC_KEY", KEY)
    monkeypatch.delenv("AEGIS_ENDPOINT", raising=False)
    with mock_aws():
        c = Clients(MOTO_ACCOUNT)
        c.get("iam").create_user(UserName="dev-svc")
        c.get("iam").create_access_key(UserName="dev-svc")
        yield c


def event_for(finding, signed=True, incident=None):
    ev = {"detail": finding}
    if signed:
        exp = int(time.time()) + 60
        ev["approval"] = {"approved_by": "farah", "expires": exp,
                          "signature": sign_approval(KEY.encode(), incident or finding["Id"], "farah", exp)}
    return ev


def active(c):
    return [k for k in c.get("iam").list_access_keys(UserName="dev-svc")["AccessKeyMetadata"] if k["Status"] == "Active"]


def test_lambda_acts_on_a_signed_approval(lam, secret_finding, capsys):
    out = lambda_handler.handler(event_for(secret_finding))
    assert out["status"] == "CONTAINED" and out["timings"]["event_to_contained_s"] > 0
    assert len(active(lam)) == 1
    assert '"step": "approval"' in capsys.readouterr().out          # the audit trail is mirrored to stdout (CloudWatch)


def test_lambda_refuses_an_unsigned_event(lam, secret_finding):
    out = lambda_handler.handler(event_for(secret_finding, signed=False))
    assert out["status"] == "DENIED" and len(active(lam)) == 1


def test_lambda_refuses_an_approval_signed_for_another_incident(lam, secret_finding):
    out = lambda_handler.handler(event_for(secret_finding, incident="some-other-finding"))
    assert out["status"] == "DENIED" and len(active(lam)) == 1


def test_lambda_without_a_key_configured_denies(lam, secret_finding, monkeypatch):
    monkeypatch.delenv("AEG_APPROVAL_HMAC_KEY")
    assert lambda_handler.handler(event_for(secret_finding))["status"] == "DENIED"


def test_lambda_survives_a_junk_event(lam):
    assert lambda_handler.handler({})["status"] == "REJECTED"


# ---- CLI
def cli(tmp_path, *args):
    return subprocess.run([sys.executable, str(ROOT / "respond.py"), "--state-dir", str(tmp_path), *args],
                          capture_output=True, text=True, timeout=60, env={**os.environ, "AEGIS_ENDPOINT": ""})


def test_cli_handle_dry_run_never_touches_aws_when_nothing_matches(tmp_path):
    """A finding no playbook wants is skipped before any AWS call, so this test needs no AWS at all."""
    f = tmp_path / "f.json"
    f.write_text(json.dumps(findings_for([cloudtrail("ScheduleKeyDeletion", "kms", req={"keyId": "k1"})])[0]))
    r = cli(tmp_path, "handle", str(f))
    assert r.returncode == 0 and "SKIPPED" in r.stdout and "Traceback" not in r.stderr
    a = cli(tmp_path, "audit")
    assert a.returncode == 0 and "chain OK: 1 records" in a.stdout


def test_cli_refuses_a_protected_identity_without_touching_aws(tmp_path):
    f = tmp_path / "f.json"
    f.write_text(json.dumps(findings_for([cloudtrail("GetSecretValue", "secretsmanager", who="root", req={"secretId": "x"},
                                                      principal_arn=f"arn:aws:iam::{MOTO_ACCOUNT}:root")])[0]))
    r = cli(tmp_path, "handle", str(f))
    assert r.returncode == 1 and "REFUSED" in r.stdout


def test_cli_refuses_auto_approval_on_real_aws(tmp_path, secret_finding):
    f = tmp_path / "f.json"
    f.write_text(json.dumps(secret_finding))
    r = cli(tmp_path, "handle", str(f), "--execute", "--approver", "auto")
    assert r.returncode != 0 and "LocalStack" in (r.stderr + r.stdout)


def test_cli_approve_without_a_pending_request_fails_cleanly(tmp_path):
    r = cli(tmp_path, "approve", "abc123")
    assert r.returncode == 1 and "no pending approval" in r.stderr


def test_lambda_package_is_deterministic_and_complete(tmp_path):
    import hashlib
    import zipfile
    hashes = []
    for i in range(2):
        subprocess.run(["bash", str(ROOT / "package_lambda.sh"), str(tmp_path / str(i))], check=True, capture_output=True)
        hashes.append(hashlib.sha256((tmp_path / str(i) / "aegis-respond.zip").read_bytes()).hexdigest())
    assert hashes[0] == hashes[1]
    names = set(zipfile.ZipFile(tmp_path / "0" / "aegis-respond.zip").namelist())
    assert {"policy.json", "aegis_respond/lambda_handler.py", "aegis_respond/engine.py"} <= names
    assert not any("__pycache__" in n or n.startswith("tests") for n in names)
