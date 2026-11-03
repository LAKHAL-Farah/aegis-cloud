from aegis_detect.asff import REQUIRED, to_alert, to_asff
from aegis_detect.engine import Engine
from aegis_detect.model import Event
from helpers import ACCT, rec


def one():
    return Engine().process([Event.from_cloudtrail(rec("ScheduleKeyDeletion", "kms", req={"keyId": "k1"}), ACCT)])[0]


def test_asff_has_every_required_top_level_field():
    f = to_asff(one())
    assert all(k in f for k in REQUIRED), [k for k in REQUIRED if k not in f]


def test_asff_values_are_well_formed():
    f = to_asff(one())
    assert f["SchemaVersion"] == "2018-10-08"
    assert f["Severity"]["Label"] in {"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert f["Types"] == ["TTPs/Impact/T1485"]
    assert f["ProductArn"].startswith("arn:aws:securityhub:")
    assert f["AwsAccountId"] == ACCT and len(f["Resources"]) == 1


def test_alert_projection_matches_the_detection_contract():
    a = to_alert(one())
    for k in ("technique", "account_id", "detected_at", "event_time", "source", "rule"):
        assert a[k]
    assert a["technique"] == "T1485" and a["account_id"] == ACCT