import boto3
import pytest
from aegis_ops import drill
from moto import mock_aws

BUCKET = "aegis-data-444444444444"


@pytest.fixture
def s3():
    with mock_aws():
        c = boto3.client("s3", region_name="us-east-1")
        c.create_bucket(Bucket=BUCKET)
        yield c


def test_drill_restores_deleted_and_overwritten_objects_bit_for_bit(s3):
    res = drill.run_drill(s3, BUCKET, n=6)
    assert res.passed and res.verified == 6 and res.restored == 6 and res.mismatches == []
    assert "PASS" in res.line()


def test_drill_cleans_up_only_its_own_prefix(s3):
    s3.put_object(Bucket=BUCKET, Key="real/data.txt", Body=b"keep me")
    drill.run_drill(s3, BUCKET, n=4)
    listing = s3.list_object_versions(Bucket=BUCKET)
    assert [v["Key"] for v in listing.get("Versions", [])] == ["real/data.txt"] and not listing.get("DeleteMarkers")


def test_keep_leaves_the_evidence(s3):
    drill.run_drill(s3, BUCKET, n=2, keep=True)
    assert s3.list_object_versions(Bucket=BUCKET, Prefix=drill.PREFIX).get("DeleteMarkers") is not None or \
        len(s3.list_object_versions(Bucket=BUCKET, Prefix=drill.PREFIX)["Versions"]) > 2


def test_drill_fails_loudly_when_versioning_cannot_help(s3, monkeypatch):
    """No good version to go back to (for example the bucket was not versioned when the data was written): FAIL."""
    monkeypatch.setattr(drill, "newest_good_version", lambda *a, **k: None)
    res = drill.run_drill(s3, BUCKET, n=2)
    assert not res.passed and res.verified == 0 and len(res.mismatches) == 2


def test_a_version_written_after_the_cutoff_is_never_restored(s3):
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket=BUCKET, Key="k", Body=b"good")
    import time
    time.sleep(1.1)
    cutoff = time.time()
    s3.put_object(Bucket=BUCKET, Key="k", Body=b"bad")
    vid = drill.newest_good_version(s3, BUCKET, "k", cutoff)
    assert s3.get_object(Bucket=BUCKET, Key="k", VersionId=vid)["Body"].read() == b"good"
