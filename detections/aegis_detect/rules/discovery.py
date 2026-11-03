from __future__ import annotations

from ..model import Event
from .base import Rule, Window, register


@register
class DiscoveryBurst(Rule):
    id = "AEG-DISC-001"
    title = "Cloud infrastructure discovery burst"
    description = ("One identity enumerated resources across several AWS services in a short time. "
                   "Typical first move after a credential is stolen.")
    technique, tactic, severity = "T1580", "Discovery", "medium"
    cooldown = 120

    @staticmethod
    def _is_discovery(e: Event) -> bool:
        return e.category == "Management" and e.name.startswith(("List", "Describe")) and e.read_only is not False

    def evaluate(self, ev, window: Window, policy):
        if not self._is_discovery(ev):
            return []
        secs = policy.threshold("discovery_window_s", 60)
        calls = window.recent(ev, secs, lambda e: e.principal == ev.principal and self._is_discovery(e))
        services = {e.service for e in calls}
        if len(calls) >= policy.threshold("discovery_min_calls", 4) and \
                len(services) >= policy.threshold("discovery_min_services", 3):
            return [self.detection(ev, evidence=calls, resource_id=ev.account_id,
                                   title=f"{self.title}: {len(calls)} calls across {len(services)} services")]
        return []