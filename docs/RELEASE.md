# Releasing and verifying

## Cut a release

1. `make gate`, `make docs-check`, `make intel-test` and `make release-test` are green.
2. `make portfolio` and commit any change to `docs/evidence/portfolio-numbers.*`.
3. Tag and push: `git tag v1.0.0 && git push origin v1.0.0`. `.github/workflows/release.yml` builds the Lambda zip, writes the
   SBOM, signs both with the workflow's GitHub identity (keyless), attests the SBOM to the zip, verifies all of it, and attaches the files.
4. Open the release and run the verification below from a clean directory. Do not skip it: the workflow verifying its own output
   proves less than you verifying it.

The keyless path has not run yet, so expect the first tag to need a fix. Record what broke in `docs/lessons-learned.md`.

## Install cosign (Linux / WSL)

The CI uses a pinned version and checks its hash. Do the same locally rather than trusting whatever a package manager has:

    curl -sSfL -o cosign https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
    echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  cosign" | sha256sum -c -
    sudo install -m 0755 cosign /usr/local/bin/cosign

## Verify a downloaded release

You need `cosign` (the scripts were run against v2.5.3 and v3.1.4) and the release files in one directory.

    sha256sum -c aegis-respond.zip.sha256

    cosign verify-blob \
      --bundle aegis-respond.zip.sigstore.json \
      --certificate-identity-regexp '^https://github.com/LAKHAL-Farah/aegis-cloud/\.github/workflows/release\.yml@refs/tags/v.*$' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      aegis-respond.zip

    cosign verify-blob-attestation --type cyclonedx \
      --bundle sbom.att.sigstore.json \
      --certificate-identity-regexp '^https://github.com/LAKHAL-Farah/aegis-cloud/\.github/workflows/release\.yml@refs/tags/v.*$' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      aegis-respond.zip

The second command checks that the SBOM was signed by the same workflow and describes this exact zip (its digest is inside the
signed statement). Repeat the first with `sbom.cdx.json` and `sbom.cdx.json.sigstore.json` to check the SBOM file itself.

To check a build made on your own machine, `RELEASE_OUT=/tmp/out COSIGN_KEY=cosign.key COSIGN_PUBKEY=cosign.pub bash release/release.sh all` does the same
with a local key. That mode uploads nothing, so the transparency log is not checked, and the script says so.

## Before announcing it

* Pin the repository on the profile and set the description and topics (a manual step on GitHub).
* README "Results" is generated: confirm `make docs-check` passes on the tagged commit.
* Record the demo video from `docs/demo-script.md`, then replace "the video itself is not recorded yet" in the README.
* Re-read "What this does not show" in the README. If a limitation was closed, move it out; if a new one appeared, add it.
