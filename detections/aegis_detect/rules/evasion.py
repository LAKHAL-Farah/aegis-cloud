from __future__ import annotations

from ..model import Event
from ..util import deep_find, flat_text
from .base import Rule, register

TRAIL_KILL = {"StopLogging", "DeleteTrail"}
TRAIL_WEAKEN = {"UpdateTrail", "PutEventSelectors", "PutInsightSelectors"}


@register
class TrailTampering(Rule):
    id = "AEG-EVAS-001"
    title = "CloudTrail logging disabled or weakened"
    description = "An audit trail was stopped, deleted or reconfigured. An attacker going dark looks like this."
    technique, tactic, severity = "T1562.008", "Defense Evasion", "critical"
    resource_type = "AwsCloudTrailTrail"
    cooldown = 60

    def evaluate(self, ev, window, policy):
        if ev.service != "cloudtrail.amazonaws.com" or ev.name not in TRAIL_KILL | TRAIL_WEAKEN:
            return []
        trail = str((deep_find(ev.request, "name", "trailName") or ["unknown"])[0])
        sev = "critical" if ev.name in TRAIL_KILL else "high"
        return [self.detection(ev, resource_id=trail, severity=sev, dedup=trail,
                               title=f"{self.title}: {ev.name} on {trail}")]


@register
class TrailNotLogging(Rule):
    """State-based twin of the rule above. It still fires if the API event itself was never recorded."""
    id = "AEG-EVAS-002"
    title = "Trail observed not logging"
    description = ("A poll of the trail's status found logging switched off. Catches the case where the "
                   "StopLogging call left no event behind (the trail that would have recorded it is the one stopped).")
    technique, tactic, severity = "T1562.008", "Defense Evasion", "critical"
    resource_type = "AwsCloudTrailTrail"
    cooldown = 300

    def evaluate(self, ev, window, policy):
        if ev.category != "Observation" or ev.name != "TrailStateObserved":
            return []
        if ev.request.get("isLogging") is not False:
            return []
        trail = str(ev.request.get("trail", "unknown"))
        return [self.detection(ev, resource_id=trail, dedup=trail, title=f"{self.title}: {trail}")]


@register
class SecurityGroupWorldOpen(Rule):
    id = "AEG-EVAS-003"
    title = "Security group opened to the internet"
    description = "An ingress rule allows 0.0.0.0/0 (or ::/0) on an administrative port or on all ports."
    technique, tactic, severity = "T1562.007", "Defense Evasion", "high"
    resource_type = "AwsEc2SecurityGroup"
    cooldown = 30

    def evaluate(self, ev: Event, window, policy):
        if ev.name != "AuthorizeSecurityGroupIngress" or not ev.succeeded:
            return []
        text = flat_text(ev.request)
        if "0.0.0.0/0" not in text and "::/0" not in text:
            return []
        protos = [str(p).lower() for p in deep_find(ev.request, "ipProtocol", "IpProtocol")]
        lows = [int(p) for p in deep_find(ev.request, "fromPort", "FromPort") if str(p).lstrip("-").isdigit()]
        highs = [int(p) for p in deep_find(ev.request, "toPort", "ToPort") if str(p).lstrip("-").isdigit()]
        all_ports = "-1" in protos or any(p == -1 for p in lows) or (lows and highs and min(lows) <= 0 and max(highs) >= 65535)
        admin = any(lo <= port <= hi for lo, hi in zip(lows, highs) for port in policy.admin_ports)
        unknown_ports = not lows
        if not (all_ports or admin or unknown_ports):
            return []
        group = str((deep_find(ev.request, "groupId") or ["unknown"])[0])
        sev = "critical" if all_ports else "high"
        return [self.detection(ev, resource_id=group, severity=sev, dedup=group,
                               title=f"{self.title}: {group}")]


@register
class InteractiveClientOnServiceIdentity(Rule):
    id = "AEG-ACCESS-001"
    title = "Service identity used from an interactive client"
    description = ("A non-interactive (service) identity called the API through a human tool such as the AWS CLI "
                   "or a browser. Signals a stolen key being used by a person. Policy-based: the range has no "
                   "benign history to learn a behavioural baseline from (see docs/localstack-limitations.md).")
    technique, tactic, severity = "T1078.004", "Initial Access", "high"
    resource_type = "AwsIamAccessKey"
    cooldown = 300

    def evaluate(self, ev, window, policy):
        if ev.category != "Management" or not ev.user_agent or not policy.is_service_identity(ev.identity_name):
            return []
        from ..util import user_agent_products
        hit = user_agent_products(ev.user_agent) & {p.lower() for p in policy.interactive_client_products}
        if not hit:
            return []
        return [self.detection(ev, resource_id=ev.identity_name, dedup=ev.identity_name,
                               title=f"{self.title}: {ev.identity_name} via {sorted(hit)[0]}")]