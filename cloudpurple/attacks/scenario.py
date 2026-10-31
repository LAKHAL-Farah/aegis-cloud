"""Scenario model and registry."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
REGISTRY: dict[str, "Scenario"] = {}


def _noop(ctx) -> None:
    return None


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    technique: str            # MITRE ATT&CK technique ID, e.g. T1562.008
    tactic: str
    description: str
    expected_events: tuple    # CloudTrail eventName values this attack should produce
    expected_detection: str   # what a good detector should notice (Stage 3 reads this)
    run: Callable
    cleanup: Callable = _noop
    data_events: bool = False  # True: only visible as CloudTrail *data* events (not in lookup_events)
    destructive: bool = False


def scenario(*, id, name, technique, tactic, description, expected_events, expected_detection,
             cleanup=None, data_events=False, destructive=False):
    def deco(fn):
        if id in REGISTRY:
            raise ValueError(f"duplicate scenario id {id}")
        REGISTRY[id] = Scenario(
            id=id, name=name, technique=technique, tactic=tactic, description=description,
            expected_events=tuple(expected_events), expected_detection=expected_detection,
            run=fn, cleanup=cleanup or _noop, data_events=data_events, destructive=destructive,
        )
        return fn
    return deco


def all_scenarios() -> list[Scenario]:
    return [REGISTRY[k] for k in sorted(REGISTRY)]