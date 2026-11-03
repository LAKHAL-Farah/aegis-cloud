"""Environment facts (policy.json) the rules consult: who is a service identity, who may edit IAM, ..."""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policy.json"


@dataclass
class Policy:
    trusted_accounts: list = field(default_factory=list)
    service_identity_patterns: list = field(default_factory=lambda: ["*-svc", "svc-*", "ci-*"])
    interactive_client_products: list = field(default_factory=lambda: ["aws-cli", "mozilla", "awsconsole"])
    iam_policy_admins: list = field(default_factory=lambda: ["root"])
    secret_readers: list = field(default_factory=list)
    admin_ports: list = field(default_factory=lambda: [22, 3389])
    thresholds: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Policy":
        data = json.loads(Path(path or DEFAULT_PATH).read_text())
        return cls(**{k: v for k, v in data.items() if not k.startswith("_")})

    def threshold(self, name: str, default: int) -> int:
        return int(self.thresholds.get(name, default))

    def is_service_identity(self, identity_name: str) -> bool:
        return any(fnmatch.fnmatch(identity_name, p) for p in self.service_identity_patterns)

    def is_policy_admin(self, identity_name: str, principal: str) -> bool:
        return identity_name in self.iam_policy_admins or principal in self.iam_policy_admins

    def is_secret_reader(self, identity_name: str, principal: str) -> bool:
        return identity_name in self.secret_readers or principal in self.secret_readers