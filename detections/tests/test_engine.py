from datetime import timedelta

from aegis_detect.engine import Engine
from aegis_detect.model import Event
from helpers import ACCT, T0, rec


def ev(r):
    return Event.from_cloudtrail(r, ACCT)


def test_same_event_twice_alerts_once():
    r = rec("CreateUser", "iam", req={"userName": "x"})
    eng = Engine()
    assert len(eng.process([ev(r)])) == 1
    assert eng.process([ev(r)]) == []


def test_cooldown_suppresses_repeats_then_releases():
    eng = Engine()
    a = rec("StopLogging", "cloudtrail", at=0, req={"name": "t"})
    b = rec("StopLogging", "cloudtrail", at=5, req={"name": "t"})
    c = rec("StopLogging", "cloudtrail", at=200, req={"name": "t"})
    assert [len(eng.process([ev(x)])) for x in (a, b, c)] == [1, 0, 1]


def test_out_of_order_batch_is_handled_by_event_time():
    recs = [rec("DescribeSecurityGroups", "ec2", at=3), rec("ListBuckets", "s3", at=0),
            rec("ListUsers", "iam", at=2), rec("DescribeInstances", "ec2", at=1)]
    assert len(Engine().process([ev(r) for r in recs])) == 1


def test_detected_at_is_stamped_by_the_engine_clock():
    stamp = T0 + timedelta(minutes=5)
    eng = Engine(now=lambda: stamp)
    det = eng.process([ev(rec("ScheduleKeyDeletion", "kms", req={"keyId": "k"}))])[0]
    assert det.detected_at == stamp and det.event_time == T0


def test_missing_identity_degrades_instead_of_crashing():
    r = rec("ScheduleKeyDeletion", "kms", req={"keyId": "k"})
    r.pop("userIdentity")
    det = Engine().process([ev(r)])[0]
    assert det.principal == "unknown"