from __future__ import annotations

from ..util import deep_find
from .base import Rule, register


@register
class IamUserCreated(Rule):
    id = "AEG-PERS-001"
    title = "IAM user created"
    description = ("A new IAM user is a classic persistence foothold. This landing zone is built on roles, "
                   "so every CreateUser deserves a human look.")
    technique, tactic, severity = "T1136.003", "Persistence", "high"
    resource_type = "AwsIamUser"
    cooldown = 30

    def evaluate(self, ev, window, policy):
        if ev.name != "CreateUser" or not ev.succeeded:
            return []
        new_user = (deep_find(ev.request, "userName") or ["unknown"])[0]
        return [self.detection(ev, resource_id=str(new_user), dedup=str(new_user),
                               title=f"{self.title}: {new_user}")]