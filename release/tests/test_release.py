"""release.sh with the real cosign, a throwaway key and no network. Skipped when cosign is not installed
(set COSIGN=/path/to/cosign, or install it: CI does)."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COSIGN = os.environ.get("COSIGN") or shutil.which("cosign")
pytestmark = pytest.mark.skipif(not COSIGN, reason="cosign is not installed")


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    subprocess.run([COSIGN, "generate-key-pair"], cwd=d, env=env, check=True, capture_output=True)
    return d / "cosign.key", d / "cosign.pub"


def run(cmd, out, keys, **extra):
    env = {**os.environ, "COSIGN": COSIGN, "COSIGN_KEY": str(keys[0]), "COSIGN_PUBKEY": str(keys[1]), "COSIGN_PASSWORD": "",
           "RELEASE_OUT": str(out), **extra}
    return subprocess.run(["bash", str(ROOT / "release" / "release.sh"), cmd], env=env, capture_output=True, text=True)


@pytest.fixture
def built(tmp_path, keys):
    out = tmp_path / "rel"
    r = run("all", out, keys)
    assert r.returncode == 0, r.stderr
    return out


def test_build_sign_verify_round_trip(built):
    for name in ("aegis-respond.zip", "aegis-respond.zip.sha256", "aegis-respond.zip.sigstore.json", "sbom.cdx.json",
                 "sbom.cdx.json.sigstore.json", "sbom.att.sigstore.json"):
        assert (built / name).is_file(), name


def test_the_checksum_file_is_portable(built, tmp_path):
    moved = tmp_path / "moved"
    shutil.copytree(built, moved)
    assert subprocess.run(["sha256sum", "-c", "aegis-respond.zip.sha256"], cwd=moved, capture_output=True).returncode == 0


def test_two_builds_of_the_same_source_have_the_same_hash(tmp_path, keys):
    a, b = tmp_path / "a", tmp_path / "b"
    assert run("build", a, keys).returncode == 0 and run("build", b, keys).returncode == 0
    assert (a / "aegis-respond.zip.sha256").read_text() == (b / "aegis-respond.zip.sha256").read_text()


def test_a_changed_zip_fails_verification(built, keys):
    with open(built / "aegis-respond.zip", "ab") as f:
        f.write(b"x")
    r = run("verify", built, keys)
    assert r.returncode == 1 and "does not match" in r.stderr


def test_a_changed_zip_with_a_fixed_up_checksum_still_fails_the_signature(built, keys):
    with open(built / "aegis-respond.zip", "ab") as f:
        f.write(b"x")
    subprocess.run("sha256sum aegis-respond.zip > aegis-respond.zip.sha256", shell=True, cwd=built, check=True)
    r = run("verify", built, keys)
    assert r.returncode == 1 and "signature INVALID" in r.stderr


def test_a_changed_sbom_fails(built, keys):
    p = built / "sbom.cdx.json"
    p.write_text(p.read_text().replace("CycloneDX", "CycloneDx", 1))
    assert run("verify", built, keys).returncode == 1


def test_an_sbom_attested_to_a_different_zip_fails(built, tmp_path, keys):
    other = tmp_path / "other"
    assert run("all", other, keys, RELEASE_VERSION="other").returncode == 0
    (other / "aegis-respond.zip").write_bytes(b"not the same zip")
    shutil.copy(other / "aegis-respond.zip", built / "aegis-respond.zip")
    (built / "aegis-respond.zip.sha256").write_text(subprocess.run(["sha256sum", "aegis-respond.zip"], cwd=built, capture_output=True, text=True).stdout)
    assert run("verify", built, keys).returncode == 1


def test_a_signature_from_another_key_is_rejected(built, tmp_path):
    env = {**os.environ, "COSIGN_PASSWORD": ""}
    other = tmp_path / "otherkeys"
    other.mkdir()
    subprocess.run([COSIGN, "generate-key-pair"], cwd=other, env=env, check=True, capture_output=True)
    assert run("verify", built, (other / "cosign.key", other / "cosign.pub")).returncode == 1
