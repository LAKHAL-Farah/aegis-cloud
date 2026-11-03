"""Small, tolerant helpers. LocalStack's CloudTrail event shapes can differ from real AWS, so rules
never index into requestParameters directly: they search it."""
from __future__ import annotations

import json
import re
from typing import Any, Iterator

ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")


def as_obj(value: Any) -> Any:
    """A JSON string becomes an object; anything else is returned unchanged."""
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in "{[":
            try:
                return json.loads(text)
            except ValueError:
                return value
    return value


def deep_items(obj: Any) -> Iterator[tuple[str, Any]]:
    """Yield every (key, value) pair in a nested structure, descending into JSON-looking strings."""
    obj = as_obj(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from deep_items(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from deep_items(item)


def deep_find(obj: Any, *names: str) -> list[Any]:
    """All values stored under any of `names` (case-insensitive) anywhere in `obj`."""
    wanted = {n.lower() for n in names}
    return [v for k, v in deep_items(obj) if k.lower() in wanted]


def flat_text(obj: Any) -> str:
    """Lower-cased JSON text of an object, for coarse 'does it mention X' checks."""
    try:
        return json.dumps(as_obj(obj), default=str).lower()
    except (TypeError, ValueError):
        return str(obj).lower()


def as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def is_false(value: Any) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def user_agent_products(user_agent: str | None) -> set[str]:
    """Product names in a User-Agent string: 'aws-cli/2.17.0 md/x' -> {'aws-cli', 'md'} (lower-case)."""
    return {m.lower() for m in re.findall(r"([A-Za-z][A-Za-z0-9._-]*)/", user_agent or "")}