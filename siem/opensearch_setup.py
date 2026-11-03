#!/usr/bin/env python3
"""Create index templates (so fields have the right types) and Dashboards data views. Safe to re-run."""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

OS = os.environ.get("OPENSEARCH_URL", "http://localhost:9200").rstrip("/")
OSD = os.environ.get("DASHBOARDS_URL", "http://localhost:5601").rstrip("/")

KEYWORD = {"type": "keyword"}
TEMPLATES = {
    "aegis-findings": {
        "index_patterns": ["aegis-findings-*"],
        "template": {"mappings": {"properties": {
            "event_time": {"type": "date"}, "detected_at": {"type": "date"}, "mttd_hint_s": {"type": "float"},
            "technique": KEYWORD, "tactic": KEYWORD, "rule": KEYWORD, "severity": KEYWORD,
            "account_id": KEYWORD, "source": KEYWORD}}}},
    "aegis-events": {
        "index_patterns": ["aegis-events-*"],
        "template": {"mappings": {"properties": {
            "event_time": {"type": "date"}, "account_id": KEYWORD, "event_name": KEYWORD, "service": KEYWORD,
            "principal": KEYWORD, "identity": KEYWORD, "user_agent": KEYWORD, "source_ip": {"type": "ip", "ignore_malformed": True},
            "error_code": KEYWORD, "category": KEYWORD}}}},
    "aegis-scorecards": {
        "index_patterns": ["aegis-scorecards*"],
        "template": {"mappings": {"properties": {
            "attack_start": {"type": "date"}, "label": KEYWORD, "id": KEYWORD, "technique": KEYWORD,
            "tactic": KEYWORD, "verdict": KEYWORD, "telemetry": KEYWORD, "detected": {"type": "boolean"},
            "mttd": {"type": "float"}, "alert_source": KEYWORD, "alert_rule": KEYWORD}}}},
}
DATA_VIEWS = {"aegis-findings": ("aegis-findings-*", "event_time"), "aegis-events": ("aegis-events-*", "event_time"),
              "aegis-scorecards": ("aegis-scorecards*", "attack_start")}


def call(method: str, url: str, body: dict | None = None, headers: dict | None = None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main() -> int:
    for name, body in TEMPLATES.items():
        code, text = call("PUT", f"{OS}/_index_template/{name}", body)
        print(f"template {name}: HTTP {code}" + ("" if code < 300 else f"  {text[:200]}"))
    for name, (pattern, time_field) in DATA_VIEWS.items():
        code, text = call("POST", f"{OSD}/api/saved_objects/index-pattern/{name}?overwrite=true",
                          {"attributes": {"title": pattern, "timeFieldName": time_field}}, {"osd-xsrf": "true"})
        if code >= 300:  # older Dashboards builds reject ?overwrite on create: retry as a plain create
            code, text = call("POST", f"{OSD}/api/saved_objects/index-pattern/{name}",
                              {"attributes": {"title": pattern, "timeFieldName": time_field}}, {"osd-xsrf": "true"})
        print(f"data view {name} ({pattern}): HTTP {code}" + ("" if code < 300 else f"  {text[:160]}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())