"""boto3 clients for the account a finding is about.

On LocalStack the access key IS the account id (ADR-0001), so the responder acts in the right account without
any stored secret. Against anything else the default credential chain is used (an assumed role in practice)."""
from __future__ import annotations

from urllib.parse import urlparse

import boto3
from botocore.config import Config

LOCAL_HOSTS = {"localhost", "127.0.0.1", "localstack", "localstack.localhost"}


def is_local(endpoint: str | None) -> bool:
    return bool(endpoint) and (urlparse(endpoint).hostname or "").lower() in LOCAL_HOSTS


class Clients:
    def __init__(self, account_id: str, endpoint: str | None = None, region: str = "us-east-1"):
        self.account_id, self.endpoint, self.region = account_id, endpoint, region
        self._cache: dict = {}

    def get(self, service: str):
        if service not in self._cache:
            kw = {"region_name": self.region,
                  "config": Config(user_agent_extra="aegis-respond", retries={"max_attempts": 2, "mode": "standard"})}
            if self.endpoint:
                kw.update(endpoint_url=self.endpoint, aws_access_key_id=self.account_id, aws_secret_access_key="test")
            self._cache[service] = boto3.client(service, **kw)
        return self._cache[service]
