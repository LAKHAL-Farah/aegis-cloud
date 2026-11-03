"""Where events come from. Every source returns Event objects; the engine does not care which one."""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .model import Event


def _maybe_gunzip(body: bytes) -> bytes:
    return gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body


class S3TrailSource:
    """Reads CloudTrail log files from the trail's S3 destination (the real delivery path).
    Needed for S3 data events (object reads and deletes), which lookup_events cannot return."""
    name = "s3"

    def __init__(self, s3, bucket: str, account_id: str, skip_existing: bool = False):
        self.s3, self.bucket, self.account_id = s3, bucket, account_id
        self.prefix = f"AWSLogs/{account_id}/CloudTrail/"
        self.done: set[str] = set()
        self.skip_existing = skip_existing
        self.files_read = 0

    def _keys(self) -> list[str]:
        keys, token = [], None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": self.prefix}
            if token:
                kw["ContinuationToken"] = token
            resp = self.s3.list_objects_v2(**kw)
            keys += [o["Key"] for o in resp.get("Contents", []) if o["Key"].endswith((".json", ".json.gz"))]
            if not resp.get("IsTruncated"):
                return sorted(keys)
            token = resp.get("NextContinuationToken")

    def prime(self) -> int:
        """Mark everything already delivered as read (watch mode starts 'from now')."""
        self.done.update(self._keys())
        return len(self.done)

    def poll(self) -> list[Event]:
        events: list[Event] = []
        for key in self._keys():
            if key in self.done:
                continue
            self.done.add(key)
            try:
                body = _maybe_gunzip(self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read())
                records = json.loads(body).get("Records", [])
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the poll
                print(f"  [warn] {self.name}: cannot read {key}: {exc}")
                continue
            self.files_read += 1
            for rec in records:
                try:
                    events.append(Event.from_cloudtrail(rec, self.account_id))
                except (KeyError, ValueError) as exc:
                    print(f"  [warn] {self.name}: skipping malformed record in {key}: {exc}")
        return events


class LookupSource:
    """CloudTrail LookupEvents: management events only, but needs no log delivery."""
    name = "lookup"

    def __init__(self, ct, account_id: str, start: datetime | None = None, overlap_s: int = 10):
        self.ct, self.account_id = ct, account_id
        self.cursor = start or datetime.now(timezone.utc)
        self.overlap = timedelta(seconds=overlap_s)

    def prime(self) -> int:
        self.cursor = datetime.now(timezone.utc)
        return 0

    def poll(self) -> list[Event]:
        start, now = self.cursor - self.overlap, datetime.now(timezone.utc)
        events, token = [], None
        while True:
            kw = {"StartTime": start, "EndTime": now + timedelta(seconds=5), "MaxResults": 50}
            if token:
                kw["NextToken"] = token
            resp = self.ct.lookup_events(**kw)
            for item in resp.get("Events", []):
                raw = item.get("CloudTrailEvent")
                try:
                    rec = json.loads(raw) if raw else {
                        "eventTime": item["EventTime"].isoformat(), "eventName": item["EventName"],
                        "eventSource": item.get("EventSource", ""), "eventID": item.get("EventId"),
                        "userIdentity": {"userName": item.get("Username", "")}}
                    events.append(Event.from_cloudtrail(rec, self.account_id))
                except (KeyError, ValueError) as exc:
                    print(f"  [warn] {self.name}: skipping malformed event: {exc}")
            token = resp.get("NextToken")
            if not token:
                break
        self.cursor = now
        return events


class TrailStateSource:
    """Polls trail status and emits an observation event. Catches 'logging is off' even when the
    StopLogging call itself left no event. It only sees what is still true at poll time."""
    name = "trail-state"

    def __init__(self, ct, account_id: str, trail: str):
        self.ct, self.account_id, self.trail = ct, account_id, trail

    def prime(self) -> int:
        return 0

    def poll(self) -> Iterable[Event]:
        try:
            logging_on = bool(self.ct.get_trail_status(Name=self.trail).get("IsLogging"))
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] {self.name}: get_trail_status failed: {exc}")
            return []
        return [Event.observation("TrailStateObserved", self.account_id, datetime.now(timezone.utc),
                                  trail=self.trail, isLogging=logging_on)]