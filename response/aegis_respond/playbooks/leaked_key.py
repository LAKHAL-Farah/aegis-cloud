"""Playbook: a long-lived IAM access key is being misused.  Contain (deactivate) -> replace (new key into Secrets
Manager) -> verify. Nothing is deleted, so the old key can be re-activated by `respond.py rollback`."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError

from ..incident import Incident
from ..policy import ResponsePolicy
from .base import Plan, Playbook, PlaybookRefusal, Step

USER_ARN = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):user/(?:.*/)?([\w+=,.@-]+)$")


def mask(key_id: str) -> str:
    return f"...{key_id[-4:]}" if len(key_id) > 4 else key_id


class LeakedKey(Playbook):
    id = "leaked_key"
    title = "Leaked access key"

    @staticmethod
    def user_of(inc: Incident) -> str:
        m = USER_ARN.match(inc.principal)
        if not m:
            raise PlaybookRefusal(f"principal {inc.principal or '(none)'} is not an IAM user, so there is no access key "
                                  "to deactivate. Role sessions expire on their own: revoke the role's sessions by hand.")
        if m.group(1) != inc.account_id:
            raise PlaybookRefusal(f"user belongs to account {m.group(1)}, not {inc.account_id}: cross-account, human only")
        return m.group(2)

    def plan(self, inc: Incident, clients, policy: ResponsePolicy) -> Plan:
        user, iam = self.user_of(inc), clients.get("iam")
        try:
            keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                raise PlaybookRefusal(f"IAM user {user} no longer exists") from None
            raise
        known = {k["AccessKeyId"]: k for k in keys}
        if inc.access_key_id in known:
            targets, match = [inc.access_key_id], "exact: the key named in the log"
        else:
            targets = [k["AccessKeyId"] for k in keys if k["Status"] == "Active"]
            match = "all active keys: the log's key id does not belong to this user"
        targets = [k for k in targets if known[k]["Status"] == "Active"]
        facts = {"user": user, "match": match, "keys": []}
        for k in keys:
            used = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {})
            facts["keys"].append({"key": mask(k["AccessKeyId"]), "status": k["Status"],
                                  "last_used": str(used.get("LastUsedDate", "never")), "service": used.get("ServiceName", "-")})
        actions: list[dict] = [{"op": "deactivate", "key_id": k} for k in targets]
        summary = [f"Deactivate access key {mask(k)} of IAM user {user}" for k in targets]
        cfg = policy.playbook(self.id)
        rotate_note = ""
        if actions and cfg.get("rotate", False):
            if len(keys) >= 2:
                rotate_note = "No replacement key: the user already has 2 keys (the IAM limit). Delete an inactive key, then rotate by hand."
            else:
                prefix = cfg.get("rotated_secret_prefix", "aegis/rotated-access-key")
                actions.append({"op": "rotate", "secret_name": f"{prefix}/{inc.account_id}/{user}"})
                summary.append(f"Create a replacement key and store it in Secrets Manager as {prefix}/{inc.account_id}/{user}")
        if rotate_note:
            summary.append(rotate_note)
        if not actions:
            summary = [f"Nothing to do: {user} has no active access keys"]
        return Plan(summary, facts, {"user": user, "actions": actions, "deactivate": targets})

    def contain(self, inc: Incident, clients, plan: Plan, policy: ResponsePolicy) -> list[Step]:
        iam, user, steps = clients.get("iam"), plan.targets["user"], []
        for act in plan.targets["actions"]:
            if act["op"] == "deactivate":
                try:
                    iam.update_access_key(UserName=user, AccessKeyId=act["key_id"], Status="Inactive")
                    steps.append(Step(f"deactivate:{act['key_id']}", True, f"deactivated {mask(act['key_id'])}",
                                      {"key_id": act["key_id"], "previous_status": "Active"}))
                except ClientError as exc:
                    steps.append(Step(f"deactivate:{act['key_id']}", False, exc.response["Error"]["Code"]))
            elif act["op"] == "rotate":
                steps.append(self._rotate(clients, user, act["secret_name"]))
        return steps

    @staticmethod
    def _rotate(clients, user: str, secret_name: str) -> Step:
        iam, sm = clients.get("iam"), clients.get("secretsmanager")
        try:
            new = iam.create_access_key(UserName=user)["AccessKey"]
        except ClientError as exc:
            return Step("rotate", False, f"create key failed: {exc.response['Error']['Code']}")
        body = json.dumps({"AccessKeyId": new["AccessKeyId"], "SecretAccessKey": new["SecretAccessKey"]})
        try:
            try:
                arn = sm.create_secret(Name=secret_name, SecretString=body,
                                       Description="AegisCloud replacement key; created by the leaked-key playbook")["ARN"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceExistsException":
                    raise
                arn = sm.put_secret_value(SecretId=secret_name, SecretString=body)["ARN"]
        except ClientError as exc:
            iam.delete_access_key(UserName=user, AccessKeyId=new["AccessKeyId"])   # never leave a key nobody can find
            return Step("rotate", False, f"could not store the new key ({exc.response['Error']['Code']}); it was deleted")
        return Step("rotate", True, f"replacement key {mask(new['AccessKeyId'])} stored in {secret_name}",
                    {"new_key_id": new["AccessKeyId"], "secret_arn": arn, "secret_name": secret_name})

    def verify(self, inc: Incident, clients, plan: Plan) -> Step:
        iam = clients.get("iam")
        keys = {k["AccessKeyId"]: k["Status"] for k in iam.list_access_keys(UserName=plan.targets["user"])["AccessKeyMetadata"]}
        still = [mask(k) for k in plan.targets["deactivate"] if keys.get(k) != "Inactive"]
        return Step("verify", not still, "all targeted keys are Inactive" if not still else f"still active: {still}")

    def rollback(self, clients, records: list[dict]) -> list[Step]:
        iam, steps = clients.get("iam"), []
        user = next((r["data"].get("facts", {}).get("user") for r in records if r["step"] == "plan"), None)
        if not user:
            return [Step("rollback", False, "the audit trail has no plan for this incident")]
        for r in records:
            if r["step"].startswith("deactivate:") and r["status"] == "ok":
                kid = r["data"]["key_id"]
                try:
                    iam.update_access_key(UserName=user, AccessKeyId=kid, Status="Active")
                    steps.append(Step(f"reactivate:{kid}", True, f"re-activated {mask(kid)}"))
                except ClientError as exc:
                    steps.append(Step(f"reactivate:{kid}", False, exc.response["Error"]["Code"]))
        return steps or [Step("rollback", False, "nothing to roll back")]
