#!/usr/bin/env python3
"""Dashboards as code: export what you built in the UI to siem/dashboards/aegis.ndjson, import it on a fresh stack.
Usage: python3 siem/dashboards.py export | import"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import uuid
from pathlib import Path

OSD = os.environ.get("DASHBOARDS_URL", "http://localhost:5601").rstrip("/")
FILE = Path(__file__).resolve().parent / "dashboards" / "aegis.ndjson"
TYPES = ["dashboard", "visualization", "search", "index-pattern"]


def export() -> int:
    req = urllib.request.Request(f"{OSD}/api/saved_objects/_export", method="POST",
                                 data=json.dumps({"type": TYPES, "includeReferencesDeep": True}).encode(),
                                 headers={"Content-Type": "application/json", "osd-xsrf": "true"})
    body = urllib.request.urlopen(req, timeout=30).read()
    FILE.parent.mkdir(parents=True, exist_ok=True)
    FILE.write_bytes(body)
    print(f"exported {len(body.splitlines())} lines to {FILE}")
    return 0


def import_() -> int:
    if not FILE.exists():
        print(f"{FILE} does not exist: build the dashboards once in the UI, then run `export`", file=sys.stderr)
        return 1
    boundary = uuid.uuid4().hex
    payload = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"aegis.ndjson\"\r\n"
               f"Content-Type: application/ndjson\r\n\r\n").encode() + FILE.read_bytes() + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{OSD}/api/saved_objects/_import?overwrite=true", data=payload, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "osd-xsrf": "true"})
    print(urllib.request.urlopen(req, timeout=30).read().decode()[:300])
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    sys.exit({"export": export, "import": import_}.get(cmd, lambda: (print(__doc__), 1)[1])())