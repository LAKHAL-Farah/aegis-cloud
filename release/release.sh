#!/usr/bin/env bash
# Build, sign, attest and verify the Lambda package.  Output: build/release/
#
#   release.sh build            deterministic zip + sha256 + CycloneDX SBOM
#   release.sh sign             sign the zip and the SBOM, attest the SBOM to the zip
#   release.sh verify           verify all three. Exits non-zero if anything does not check out
#   release.sh all              build, sign, verify
#
# Two signing modes (cosign v2.5 and v3.1 were both run against this script):
#   local key (offline, used by the tests):  COSIGN_KEY=cosign.key COSIGN_PUBKEY=cosign.pub [COSIGN_PASSWORD=...]
#   keyless (GitHub Actions OIDC, no key to guard): leave COSIGN_KEY unset. verify needs RELEASE_IDENTITY_RE.
# In local-key mode nothing is uploaded: no transparency-log entry exists, so verify uses --insecure-ignore-tlog and says so.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
out="${RELEASE_OUT:-$root/build/release}"
cosign="${COSIGN:-cosign}"
zip="$out/aegis-respond.zip"
sbom="$out/sbom.cdx.json"
issuer="https://token.actions.githubusercontent.com"
identity_re="${RELEASE_IDENTITY_RE:-^https://github.com/LAKHAL-Farah/aegis-cloud/\.github/workflows/release\.yml@refs/tags/v.*\$}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "release.sh: '$1' is required" >&2; exit 2; }; }

# How to sign with a local key and upload nothing. cosign v3 needs a (here empty) signing config; v2 has --tlog-upload=false.
offline_flags() {
  local major; major="$("$cosign" version 2>&1 | sed -n 's/^GitVersion: *v\{0,1\}\([0-9][0-9]*\)\..*/\1/p' | head -1)"
  if [ "${major:-3}" -ge 3 ]; then
    local f="$out/.signing-config.json"
    cat > "$f" <<'JSON'
{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","caUrls":[],"oidcUrls":[],"rekorTlogUrls":[],"rekorTlogConfig":{"selector":"ANY"},"tsaUrls":[],"tsaConfig":{"selector":"ANY"}}
JSON
    echo "--signing-config $f"
  else
    echo "--tlog-upload=false"
  fi
}

build() {
  need python3
  mkdir -p "$out"
  bash "$root/response/package_lambda.sh" "$out" >/dev/null
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 1767225600)}" \
    python3 "$here/sbom.py" "$zip" --version "${RELEASE_VERSION:-}" --out "$sbom" >/dev/null
  echo "built $(basename "$zip")  sha256 $(cut -d' ' -f1 "$zip.sha256")"
}

sign() {
  need "$cosign"
  [ -f "$zip" ] && [ -f "$sbom" ] || { echo "release.sh: run 'build' first" >&2; exit 2; }
  if [ -n "${COSIGN_KEY:-}" ]; then
    local flags; read -r -a flags <<< "$(offline_flags)"
    "$cosign" sign-blob --key "$COSIGN_KEY" "${flags[@]}" --bundle "$zip.sigstore.json" --yes "$zip" >/dev/null
    "$cosign" sign-blob --key "$COSIGN_KEY" "${flags[@]}" --bundle "$sbom.sigstore.json" --yes "$sbom" >/dev/null
    "$cosign" attest-blob --key "$COSIGN_KEY" "${flags[@]}" --predicate "$sbom" --type cyclonedx \
      --bundle "$out/sbom.att.sigstore.json" --yes "$zip" >/dev/null
  else
    "$cosign" sign-blob --bundle "$zip.sigstore.json" --yes "$zip" >/dev/null
    "$cosign" sign-blob --bundle "$sbom.sigstore.json" --yes "$sbom" >/dev/null
    "$cosign" attest-blob --predicate "$sbom" --type cyclonedx --bundle "$out/sbom.att.sigstore.json" --yes "$zip" >/dev/null
  fi
  echo "signed zip and SBOM, attested SBOM to the zip"
}

verify() {
  need "$cosign"
  local mode=(--certificate-identity-regexp "$identity_re" --certificate-oidc-issuer "$issuer")
  if [ -n "${COSIGN_PUBKEY:-}" ]; then
    mode=(--key "$COSIGN_PUBKEY" --insecure-ignore-tlog)
    echo "local-key mode: transparency log not checked (nothing was uploaded)"
  fi
  ( cd "$out" && sha256sum -c aegis-respond.zip.sha256 >/dev/null ) || { echo "release.sh: sha256 does not match" >&2; exit 1; }
  "$cosign" verify-blob "${mode[@]}" --bundle "$zip.sigstore.json" "$zip" >/dev/null 2>&1 || { echo "release.sh: zip signature INVALID" >&2; exit 1; }
  "$cosign" verify-blob "${mode[@]}" --bundle "$sbom.sigstore.json" "$sbom" >/dev/null 2>&1 || { echo "release.sh: SBOM signature INVALID" >&2; exit 1; }
  "$cosign" verify-blob-attestation "${mode[@]}" --type cyclonedx --bundle "$out/sbom.att.sigstore.json" "$zip" >/dev/null 2>&1 \
    || { echo "release.sh: SBOM attestation INVALID (not bound to this zip)" >&2; exit 1; }
  echo "verified: zip, SBOM, and the attestation that binds them"
}

case "${1:-}" in
  build) build ;;
  sign) sign ;;
  verify) verify ;;
  all) build; sign; verify ;;
  *) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
