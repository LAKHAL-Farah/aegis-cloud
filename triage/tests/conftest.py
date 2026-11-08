import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for p in (ROOT / "response" / "tests", ROOT / "response", ROOT / "detections", HERE.parent):
    sys.path.insert(0, str(p))

import pytest


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for name in [n for n in os.environ if n.startswith("AWS_ENDPOINT_URL") or n.startswith("AEG_TRIAGE") or n == "ANTHROPIC_API_KEY"]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
