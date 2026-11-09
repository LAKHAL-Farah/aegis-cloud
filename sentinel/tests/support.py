"""Tiny snapshot builder so each test states only the IAM it is about."""
ACCT = "111122223333"


def arn(kind, name):
    return f"arn:aws:iam::{ACCT}:{kind}/{name}"


def allow(action, resource="*", **kw):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **kw}


def doc(*stmts):
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def snap(users=(), roles=(), groups=(), policies=()):
    s = {"schema": "aegis.iam-snapshot/v1", "account_id": ACCT, "collected_at": "t", "principals": {}, "policies": {}, "unresolved": []}
    for name, kw in users:
        s["principals"][arn("user", name)] = {"kind": "user", "name": name, "boundary": kw.get("boundary"), "trust": None,
                                              "groups": [arn("group", g) for g in kw.get("groups", [])],
                                              "inline": kw.get("inline", {}), "attached": kw.get("attached", [])}
    for name, kw in roles:
        s["principals"][arn("role", name)] = {"kind": "role", "name": name, "boundary": kw.get("boundary"), "groups": [],
                                              "trust": kw.get("trust"), "inline": kw.get("inline", {}), "attached": kw.get("attached", [])}
    for name, kw in groups:
        s["principals"][arn("group", name)] = {"kind": "group", "name": name, "boundary": None, "trust": None, "groups": [],
                                               "inline": kw.get("inline", {}), "attached": kw.get("attached", [])}
    for name, kw in policies:
        s["policies"][arn("policy", name)] = {"name": name, "aws_managed": kw.get("aws_managed", False), "bundled": False,
                                              "doc": kw["doc"], "other_versions": kw.get("other_versions", [])}
    return s


def trust_user(name, **extra):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": arn("user", name)}, "Action": "sts:AssumeRole", **extra}]}


def trust_root(**extra):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "sts:AssumeRole", **extra}]}


def trust_service(svc):
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": svc}, "Action": "sts:AssumeRole"}]}
