from __future__ import annotations

from ..util import deep_find
from .base import Rule, register


@register
class SecretRead(Rule):
    id = "AEG-CRED-001"
    title = "Secret read by an unexpected identity"
    description = ("GetSecretValue by an identity that is not on the secret_readers list in policy.json. "
                   "Expect noise from your own Terraform runs: that is what a tuning backlog looks like.")
    technique, tactic, severity = "T1555.006", "Credential Access", "medium"
    resource_type = "AwsSecretsManagerSecret"
    cooldown = 60

    def evaluate(self, ev, window, policy):
        if ev.name not in {"GetSecretValue", "BatchGetSecretValue"} or not ev.succeeded:
            return []
        if policy.is_secret_reader(ev.identity_name, ev.principal):
            return []
        secret = str((deep_find(ev.request, "secretId") or ["unknown"])[0])
        return [self.detection(ev, resource_id=secret, dedup=secret, title=f"{self.title}: {secret}")]