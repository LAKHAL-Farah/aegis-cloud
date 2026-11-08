"""Everything an attacker can influence is untrusted text: principal names, bucket names, user agents, titles built from
them. This module turns such strings into something safe to show a person in chat, and checks anything a model
writes before it reaches the approval prompt."""
from __future__ import annotations

import re

CONTROL = re.compile(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")      # control, zero-width and bidi characters
MARKUP = re.compile(r"[<>`|\\{}\[\]*_~]")                  # stripped from untrusted values
CHAT_MARKUP = re.compile(r"[<>`|\\{}\[\]]")                     # refused in model text (underscores in prose are fine)
URL = re.compile(r"(https?://|ftp://|www\.|\b[a-z0-9-]+\.(com|net|org|io|ru|cn|xyz)\b)", re.I)
MENTION = re.compile(r"(<[!@#]|@(channel|here|everyone)\b|<!subteam)", re.I)
KEY_ID = re.compile(r"\b(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,}\b")
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
EMOJI_CODE = re.compile(r":[a-z0-9_+-]{2,}:", re.I)       # :white_check_mark: in an advisory would look like an approval prompt
ALLOWED_EVENT_NAME = re.compile(r"^[A-Za-z0-9]{1,64}$")


def clean(value, limit: int = 60) -> str:
    """A short, inert rendering of an untrusted value. Lossy on purpose."""
    s = CONTROL.sub(" ", str(value))
    s = MARKUP.sub("", s).replace("@", "(at)").replace(":", "-")
    s = s.replace(".", "·")                                  # a name that looks like a domain must not become a chat link
    s = re.sub(r"\s+", " ", s).strip()
    s = KEY_ID.sub("[key-id]", s)
    s = LONG_TOKEN.sub("[token]", s)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def tail(value, limit: int = 60) -> str:
    """Last path segment of an ARN or a path: enough for a person, and it avoids echoing whole identifiers."""
    s = str(value).rstrip("/")
    for sep in ("/", ":"):
        s = s.rsplit(sep, 1)[-1]
    return clean(s, limit)


def event_name(value) -> str:
    return str(value) if ALLOWED_EVENT_NAME.match(str(value)) else "unknown"


def violation(text: str) -> str:
    """Why a model-written string must not be shown, or "" if it is acceptable."""
    if CONTROL.search(text):
        return "control or invisible characters"
    if URL.search(text):
        return "a link"
    if MENTION.search(text):
        return "a chat mention"
    if KEY_ID.search(text) or LONG_TOKEN.search(text):
        return "something that looks like a credential"
    if EMOJI_CODE.search(text):
        return "an emoji code (could imitate the approval prompt)"
    if CHAT_MARKUP.search(text):
        return "chat markup"
    return ""
