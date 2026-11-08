#!/usr/bin/env python3
"""Validate an SBOM against the official CycloneDX 1.5 JSON schema. Needs a network (it fetches the schema from the
CycloneDX repository) and `pip install jsonschema referencing`, so it is a make target, not a unit test.
  validate_sbom.py build/release/sbom.cdx.json
"""
import json
import sys
import urllib.request

BASE = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema/"


def fetch(name):
    with urllib.request.urlopen(BASE + name, timeout=20) as r:
        return json.load(r)


def main(path: str) -> int:
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    reg = Registry()
    for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
        reg = reg.with_resource(f"http://cyclonedx.org/schema/{name}", Resource.from_contents(fetch(name)))
    errors = list(Draft7Validator(fetch("bom-1.5.schema.json"), registry=reg).iter_errors(json.load(open(path))))
    for e in errors[:10]:
        print("invalid:", e.message[:200])
    print("CycloneDX 1.5 schema:", "valid" if not errors else f"{len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
