from __future__ import annotations

from ..util import as_obj, as_list, deep_find
from .base import Rule, register


def _grants_everything(document) -> bool:
    doc = as_obj(document)
    if not isinstance(doc, dict):
        return False
    for st in as_list(doc.get("Statement")):
        if isinstance(st, dict) and st.get("Effect") == "Allow":
            actions = [str(a) for a in as_list(st.get("Action"))]
            resources = [str(r) for r in as_list(st.get("Resource"))]
            if "*" in actions and "*" in resources:
                return True
    return False


@register
class PolicyVersionByNonAdmin(Rule):
    id = "AEG-PRIV-001"
    title = "IAM policy rewritten by a non-administrator"
    description = ("CreatePolicyVersion / SetDefaultPolicyVersion by an identity that is not an IAM policy "
                   "administrator. A user who can edit a policy attached to itself can grant itself anything.")
    technique, tactic, severity = "T1098", "Privilege Escalation", "high"
    resource_type = "AwsIamPolicy"
    cooldown = 30

    def evaluate(self, ev, window, policy):
        if ev.name not in {"CreatePolicyVersion", "SetDefaultPolicyVersion"} or not ev.succeeded:
            return []
        if policy.is_policy_admin(ev.identity_name, ev.principal):
            return []
        arn = str((deep_find(ev.request, "policyArn") or ["unknown"])[0])
        document = (deep_find(ev.request, "policyDocument") or [None])[0]
        sev = "critical" if _grants_everything(document) else "high"
        return [self.detection(ev, resource_id=arn, severity=sev, dedup=arn,
                               title=f"{self.title}: {arn.rsplit('/', 1)[-1]}")]