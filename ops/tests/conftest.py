import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parents[1] / "detections"))
sys.path.insert(0, str(HERE.parents[1] / "response"))


import pytest


@pytest.fixture(autouse=True)
def _isolate_from_localstack_env(monkeypatch):
    """`source scripts/env.sh` exports AWS_ENDPOINT_URL (boto3 honours it, moto does not intercept it), so without this
    the moto-backed tests would try to reach a real LocalStack. Tests never talk to a network."""
    import os
    for name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
