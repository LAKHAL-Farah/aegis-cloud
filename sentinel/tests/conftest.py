import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import pytest



@pytest.fixture(autouse=True)
def _isolate_from_localstack_env(monkeypatch):
    for name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: loads every botocore service model (about 6 s)")
