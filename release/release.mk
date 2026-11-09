# Stage 7 targets: release, SBOM, signing, headline numbers, docs checks. Included by the main Makefile.
REL_OUT := build/release

.PHONY: release-test release-build release-sign release-verify release-all sbom-validate portfolio docs-check docs-test secrets-scan

release-test:  ## SBOM and signing tests (signing tests need cosign on PATH or COSIGN=/path/to/cosign; they skip otherwise)
> $(PY) -m pytest release/tests -q

release-build:  ## deterministic Lambda zip + sha256 + CycloneDX SBOM into build/release/
> bash release/release.sh build

release-sign:  ## sign zip and SBOM, attest the SBOM to the zip. Local key: COSIGN_KEY=... COSIGN_PUBKEY=...; otherwise keyless (CI)
> bash release/release.sh sign

release-verify:  ## verify checksum, both signatures and the attestation; exit 1 on any failure
> bash release/release.sh verify

release-all: release-build release-sign release-verify  ## build, sign, verify

sbom-validate:  ## check the SBOM against the official CycloneDX 1.5 schema (needs network and `pip install jsonschema referencing`)
> $(PY) release/validate_sbom.py $(REL_OUT)/sbom.cdx.json

portfolio:  ## recompute the headline numbers and the CV line from the evidence files
> $(PY) release/portfolio.py --write

docs-test:  ## architecture paths, ADR numbering, README numbers against the evidence
> $(PY) -m pytest docs/tests -q

docs-check: docs-test  ## fails if the README disagrees with the evidence
> $(PY) release/portfolio.py --check README.md

secrets-scan:  ## gitleaks over the history (needs the gitleaks binary)
> gitleaks git . --config .gitleaks.toml --redact --no-banner
