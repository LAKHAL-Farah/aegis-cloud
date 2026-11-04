import pytest
from rsupport import Approve, AuditLog, FakeTelegram, Ledger, Recorder, ResponsePolicy, Responder, cloudtrail, findings_for


@pytest.fixture
def secret_finding():
    """A service identity reads a secret: AEG-CRED-001 (T1555.006), a credential-misuse finding."""
    return findings_for([cloudtrail("GetSecretValue", "secretsmanager", req={"secretId": "prod/db"})])[0]


@pytest.fixture
def public_bucket_finding():
    return findings_for([cloudtrail("PutPublicAccessBlock", "s3", req={
        "bucketName": "data-bucket", "PublicAccessBlockConfiguration": {"BlockPublicAcls": False}})])[0]


@pytest.fixture
def make_responder(tmp_path):
    def build(approver=None, execute=True, notifier=None, policy=None, clock=None, **kw):
        notifier = notifier or Recorder()
        r = Responder(policy=policy or ResponsePolicy.load(), approver=approver or Approve(), notifier=notifier,
                      audit=AuditLog(tmp_path / "audit.jsonl"), ledger=Ledger(tmp_path / "ledger.json"),
                      execute=execute, **({"clock": clock} if clock else {}), **kw)
        r.notifier_ref = notifier
        return r
    return build


@pytest.fixture
def telegram():
    t = FakeTelegram()
    yield t
    t.close()
