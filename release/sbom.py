#!/usr/bin/env python3
"""A CycloneDX 1.5 SBOM for the Lambda package, written without any network and without a scanner.

What it lists: the artifact (with its sha256), every file inside the zip (with its sha256), and the runtime
dependencies named in response/requirements.txt. boto3 is provided by the Lambda runtime, not shipped in the zip, so it is
listed with scope "excluded" and an unpinned constraint. The composition says "incomplete_first_party_only" because that is
the truth: first-party files are complete, third-party versions are decided by the runtime.

Deterministic: the same zip and timestamp give the same document (serial number is a UUIDv5 of the zip's hash).

  sbom.py ZIP [--requirements FILE] [--timestamp ISO] [--version V] [--out FILE]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

DEV_ONLY = {"pytest", "moto"}
NAMESPACE = uuid.UUID("2f3b6f0e-5d1a-4e0b-9c7a-1c2d3e4f5a6b")      # fixed, so the serial number depends only on the zip


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.-]+)(\[[^\]]*\])?\s*(.*)$", line)
        if m and m.group(1).lower() not in DEV_ONLY:
            out.append((m.group(1).lower(), m.group(3).strip()))
    return out


def build(zip_path: Path, requirements: str = "", timestamp: str | None = None, version: str = "") -> dict:
    blob = Path(zip_path).read_bytes()
    digest = sha256_hex(blob)
    name = Path(zip_path).name
    ts = timestamp or datetime.fromtimestamp(int(os.environ.get("SOURCE_DATE_EPOCH", datetime.now(timezone.utc).timestamp())),
                                             timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    top = {"type": "application", "bom-ref": f"artifact:{name}", "name": name, "hashes": [{"alg": "SHA-256", "content": digest}]}
    if version:
        top["version"] = version
    components = []
    with zipfile.ZipFile(zip_path) as z:
        for info in sorted(z.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            components.append({"type": "file", "bom-ref": f"file:{info.filename}", "name": info.filename,
                               "hashes": [{"alg": "SHA-256", "content": sha256_hex(z.read(info))}]})
    deps = []
    for pkg, constraint in parse_requirements(requirements):
        ref = f"pkg:pypi/{pkg}"
        components.append({"type": "library", "bom-ref": ref, "name": pkg, "purl": ref, "scope": "excluded",
                           "properties": [{"name": "aegis:provided-by", "value": "aws-lambda-python-runtime"},
                                          {"name": "aegis:constraint", "value": constraint or "unpinned"}]})
        deps.append(ref)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(NAMESPACE, digest)}",
        "metadata": {"timestamp": ts, "component": top,
                     "tools": {"components": [{"type": "application", "name": "aegis-sbom", "version": "1"}]}},
        "components": components,
        "dependencies": [{"ref": top["bom-ref"], "dependsOn": deps}],
        "compositions": [{"aggregate": "incomplete_first_party_only", "assemblies": [top["bom-ref"]]}],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("zip")
    ap.add_argument("--requirements", default=str(Path(__file__).resolve().parents[1] / "response" / "requirements.txt"))
    ap.add_argument("--timestamp")
    ap.add_argument("--version", default="")
    ap.add_argument("--out")
    a = ap.parse_args()
    req = Path(a.requirements).read_text() if Path(a.requirements).is_file() else ""
    doc = json.dumps(build(Path(a.zip), req, a.timestamp, a.version), indent=2, sort_keys=True)
    if a.out:
        Path(a.out).write_text(doc + "\n")
        print(f"wrote {a.out}")
    else:
        print(doc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
