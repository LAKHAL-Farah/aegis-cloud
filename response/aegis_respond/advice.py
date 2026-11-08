"""Advice lines (ADR-0020) are shown apart from the plan, because they are not part of what runs.

The engine tags every advisory line so it starts with "[". Plan lines never do, which a test checks for every playbook."""
from __future__ import annotations

HEADER = "Advice (not part of the plan, cannot change what runs)"


def tag(line) -> str:
    s = str(line).strip()
    return s if s.startswith("[") else f"[advice] {s}"


def split(lines) -> tuple[list[str], list[str]]:
    lines = [str(x) for x in lines]
    return [x for x in lines if not x.startswith("[")], [x for x in lines if x.startswith("[")]
