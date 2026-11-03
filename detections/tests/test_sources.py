import gzip
import io
import json
from datetime import datetime, timezone

from aegis_detect.sources import LookupSource, S3TrailSource, TrailStateSource
from helpers import ACCT, rec


class FakeS3:
    def __init__(self, files):
        self.files = files

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        return {"Contents": [{"Key": k} for k in sorted(self.files) if k.startswith(Prefix)], "IsTruncated": False}

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.files[Key])}


def gz(records):
    return gzip.compress(json.dumps({"Records": records}).encode())


def test_s3_source_reads_gzip_and_plain_and_skips_garbage_and_repeats():
    base = f"AWSLogs/{ACCT}/CloudTrail/us-east-1/2026/10/31/"
    fake = FakeS3({base + "a.json.gz": gz([rec("CreateUser", "iam")]),
                   base + "b.json": json.dumps({"Records": [rec("ListUsers", "iam")]}).encode(),
                   base + "c.json": b"not json"})
    src = S3TrailSource(fake, "bucket", ACCT)
    events = src.poll()
    assert sorted(e.name for e in events) == ["CreateUser", "ListUsers"] and src.files_read == 2
    assert src.poll() == []


def test_s3_source_prime_skips_history():
    base = f"AWSLogs/{ACCT}/CloudTrail/us-east-1/2026/10/31/"
    fake = FakeS3({base + "a.json.gz": gz([rec("CreateUser", "iam")])})
    src = S3TrailSource(fake, "bucket", ACCT)
    assert src.prime() == 1 and src.poll() == []
    fake.files[base + "z.json.gz"] = gz([rec("ListUsers", "iam")])
    assert [e.name for e in src.poll()] == ["ListUsers"]


class FakeCT:
    def __init__(self, items=None, logging_on=True):
        self.items, self.logging_on = items or [], logging_on

    def lookup_events(self, **kw):
        return {"Events": self.items}

    def get_trail_status(self, Name):
        return {"IsLogging": self.logging_on}


def test_lookup_source_parses_the_embedded_cloudtrail_json():
    item = {"EventId": "x", "EventName": "StopLogging", "CloudTrailEvent": json.dumps(rec("StopLogging", "cloudtrail"))}
    events = LookupSource(FakeCT([item]), ACCT, start=datetime.now(timezone.utc)).poll()
    assert [e.name for e in events] == ["StopLogging"]


def test_lookup_source_survives_events_without_embedded_json():
    item = {"EventId": "x", "EventName": "StopLogging", "EventSource": "cloudtrail.amazonaws.com",
            "EventTime": datetime.now(timezone.utc), "Username": "dev-svc"}
    events = LookupSource(FakeCT([item]), ACCT).poll()
    assert events and events[0].identity_name == "dev-svc"


def test_trail_state_source_reports_logging_off():
    ev = list(TrailStateSource(FakeCT(logging_on=False), ACCT, "t").poll())[0]
    assert ev.request["isLogging"] is False and ev.category == "Observation"


def test_opensearch_bulk_body_is_valid_ndjson_and_skips_observations():
    from aegis_detect.model import Event
    from aegis_detect.sinks import OpenSearchEvents
    from helpers import T0
    ev = Event.from_cloudtrail(rec("CreateUser", "iam"), ACCT)
    obs = Event.observation("TrailStateObserved", ACCT, T0, trail="t", isLogging=True)
    body = OpenSearchEvents.bulk_body([ev, obs])
    lines = body.strip().split("\n")
    assert len(lines) == 2 and body.endswith("\n")
    action, doc = (json.loads(x) for x in lines)
    assert action["index"]["_index"].startswith("aegis-events-") and doc["event_name"] == "CreateUser"
    assert OpenSearchEvents.bulk_body([obs]) == ""