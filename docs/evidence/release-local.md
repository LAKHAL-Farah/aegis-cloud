# Release build, sign, verify and tamper check (local key, WSL), 2026-11-08

Console output pasted by the repository owner, run with `COSIGN_KEY` and `COSIGN_PUBKEY` set to a throwaway key pair and no network
signing (cosign's transparency log not used).

```
make release-all
  built aegis-respond.zip  sha256 9ea4a36094cbd72e2379a08a7ae02154b8309e339e34337957c85104c33b6c07
  signed zip and SBOM, attested SBOM to the zip
  local-key mode: transparency log not checked (nothing was uploaded)
  verified: zip, SBOM, and the attestation that binds them

printf x >> build/release/aegis-respond.zip ; make release-verify
  sha256sum: WARNING: 1 computed checksum did NOT match
  release.sh: sha256 does not match                      (exit 1)

make release-build
  built aegis-respond.zip  sha256 9ea4a36094cbd72e2379a08a7ae02154b8309e339e34337957c85104c33b6c07
```

What it shows: the full flow works on the owner's machine; a one-byte change is caught; and a rebuild after the change gives the same hash as the
first build, so the package is reproducible there. Not shown: the keyless GitHub Actions path, and a deploy-time check of the signature.
