import hashlib
import json
import zipfile

import pytest
import sbom


@pytest.fixture
def zpath(tmp_path):
    p = tmp_path / "pkg.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("aegis_respond/engine.py", "print('x')\n")
        z.writestr("policy.json", "{}\n")
    return p


REQ = "boto3>=1.34\npytest>=8.0,<9\nmoto[iam]>=5.0,<6  # tests only\n"


def test_lists_the_artifact_every_file_and_the_runtime_dependency(zpath):
    doc = sbom.build(zpath, REQ, "2026-11-06T00:00:00Z")
    top = doc["metadata"]["component"]
    assert top["hashes"][0]["content"] == hashlib.sha256(zpath.read_bytes()).hexdigest()
    files = {c["name"]: c["hashes"][0]["content"] for c in doc["components"] if c["type"] == "file"}
    assert files == {"aegis_respond/engine.py": hashlib.sha256(b"print('x')\n").hexdigest(), "policy.json": hashlib.sha256(b"{}\n").hexdigest()}
    libs = [c for c in doc["components"] if c["type"] == "library"]
    assert [c["name"] for c in libs] == ["boto3"]                          # pytest and moto are test tools, not in the package
    assert libs[0]["scope"] == "excluded" and {"name": "aegis:constraint", "value": ">=1.34"} in libs[0]["properties"]


def test_it_says_what_it_does_not_know(zpath):
    doc = sbom.build(zpath, REQ, "2026-11-06T00:00:00Z")
    assert doc["compositions"][0]["aggregate"] == "incomplete_first_party_only"      # the schema key is `aggregate` (found by validating)


def test_same_zip_and_time_give_the_same_document(zpath):
    a, b = (json.dumps(sbom.build(zpath, REQ, "2026-11-06T00:00:00Z"), sort_keys=True) for _ in range(2))
    assert a == b
    assert sbom.build(zpath, REQ, "x")["serialNumber"] == sbom.build(zpath, REQ, "y")["serialNumber"]


def test_a_different_zip_gets_a_different_serial_number(zpath, tmp_path):
    other = tmp_path / "o.zip"
    with zipfile.ZipFile(other, "w") as z:
        z.writestr("a", "b")
    assert sbom.build(zpath, REQ, "t")["serialNumber"] != sbom.build(other, REQ, "t")["serialNumber"]


def test_required_cyclonedx_fields_are_present(zpath):
    doc = sbom.build(zpath, REQ, "2026-11-06T00:00:00Z")
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5" and doc["serialNumber"].startswith("urn:uuid:")
    refs = {c["bom-ref"] for c in doc["components"]} | {doc["metadata"]["component"]["bom-ref"]}
    assert all(d["ref"] in refs and set(d["dependsOn"]) <= refs for d in doc["dependencies"])
    assert len(refs) == len(doc["components"]) + 1                          # bom-refs are unique


def test_real_package_is_listed_completely():
    import subprocess
    import tempfile
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["bash", str(root / "response" / "package_lambda.sh"), d], check=True, capture_output=True)
        with zipfile.ZipFile(Path(d) / "aegis-respond.zip") as z:
            names = {n for n in z.namelist() if not n.endswith("/")}
        doc = sbom.build(Path(d) / "aegis-respond.zip", (root / "response" / "requirements.txt").read_text(), "t")
    assert {c["name"] for c in doc["components"] if c["type"] == "file"} == names and "policy.json" in names
