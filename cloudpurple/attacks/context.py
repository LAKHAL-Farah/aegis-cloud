"""Who attacks whom, and the boto3 clients to do it."""
from __future__ import annotations

from dataclasses import dataclass

import boto3
from botocore.config import Config


@dataclass
class Target:
    name: str
    account_id: str
    hardened: bool
    resources: dict
    credentials: dict


def quiet(fn, *args, **kwargs):
    """Call fn, swallow any error (used only in cleanup, which must be safe to repeat)."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return None


class Context:
    def __init__(self, target: Target, endpoint: str, region: str, run_id: str, as_root: bool = False):
        self.target = target
        self.endpoint = endpoint
        self.region = region
        self.run_id = run_id
        self.as_root = as_root
        self.state: dict = {}   # scratch space shared by a scenario's run() and cleanup()

    @property
    def hardened(self) -> bool:
        return self.target.hardened

    @property
    def res(self) -> dict:
        return self.target.resources

    def _client(self, service: str, key_id: str, secret: str, user_agent: str | None = None):
        cfg = Config(user_agent_extra=user_agent or f"cloudpurple/{self.run_id}",
                     retries={"max_attempts": 1, "mode": "standard"})
        return boto3.client(service, endpoint_url=self.endpoint, region_name=self.region,
                            aws_access_key_id=key_id, aws_secret_access_key=secret, config=cfg)

    def attacker(self, service: str, user_agent: str | None = None):
        """The stolen dev-svc key (or the account root with --as-root, to isolate SCP effects)."""
        if self.as_root:
            return self.admin(service, user_agent)
        c = self.target.credentials
        return self._client(service, c["attacker_key_id"], c["attacker_secret"], user_agent)

    def intern(self, service: str):
        c = self.target.credentials
        return self._client(service, c["intern_key_id"], c["intern_secret"])

    def admin(self, service: str, user_agent: str | None = None):
        """Account root (on LocalStack the access key IS the account id). Cleanup and verification only."""
        return self._client(service, self.target.account_id, "test", user_agent or "cloudpurple-admin")