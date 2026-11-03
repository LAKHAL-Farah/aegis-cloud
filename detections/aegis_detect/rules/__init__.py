"""Importing this package registers every rule."""
from . import credential, discovery, evasion, exfiltration, impact, persistence, privilege  # noqa: F401
from .base import REGISTRY, Rule, Window, register  # noqa: F401


def all_rules() -> list[Rule]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]