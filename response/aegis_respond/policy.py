"""response/policy.json: which findings trigger which playbook, who must never be touched, how long to wait."""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policy.json"


@dataclass
class ResponsePolicy:
    protected_identities: list = field(default_factory=lambda: ["root", "aegis-*", "break-glass-*"])
    approval_timeout_s: int = 120
    min_severity: str = "medium"
    cooldown_s: int = 300
    playbooks: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "ResponsePolicy":
        data = json.loads(Path(path or DEFAULT_PATH).read_text())
        return cls(**{k: v for k, v in data.items() if not k.startswith("_")})

    def is_protected(self, identity: str) -> bool:
        return any(fnmatch.fnmatch(identity, p) for p in self.protected_identities)

    def playbook(self, pid: str) -> dict:
        return self.playbooks.get(pid, {})

    def enabled(self, pid: str) -> bool:
        return bool(self.playbook(pid).get("enabled", False))
