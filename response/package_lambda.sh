#!/usr/bin/env bash
# Build the Lambda deployment package: aegis_respond/ + policy.json at the zip root. boto3 comes from the runtime.
#   handler: aegis_respond.lambda_handler.handler     env: AEG_APPROVAL_HMAC_KEY (required), TELEGRAM_*, SLACK_WEBHOOK_URL
# Needs only python3 (no `zip` binary). The archive is deterministic: sorted names, fixed timestamps and modes,
# so the same source always gives the same sha256. Stage 7 signs it with Cosign; this hash is what gets attested.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$here/../build/lambda}"
mkdir -p "$out"
python3 - "$here" "$out/aegis-respond.zip" <<'PY'
import sys, zipfile
from pathlib import Path

here, target = Path(sys.argv[1]), Path(sys.argv[2])
files = [(p.relative_to(here).as_posix(), p) for p in (here / "aegis_respond").rglob("*.py")]
files.append(("policy.json", here / "policy.json"))
with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
    for name, path in sorted(files):
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type, info.external_attr = zipfile.ZIP_DEFLATED, 0o644 << 16
        z.writestr(info, path.read_bytes())
PY
sha256sum "$out/aegis-respond.zip" | tee "$out/aegis-respond.zip.sha256"
