#!/usr/bin/env bash
# Build siem/wazuh/ossec.conf: the image's own default config plus one <localfile> that reads the detector's
# raw-event mirror. We patch a copy of the default instead of shipping a whole config, so a Wazuh upgrade
# only needs this script re-run.
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE=$(grep -E 'image: wazuh/wazuh-manager' docker-compose.siem.yml | awk '{print $2}')
mkdir -p build/siem/events build/siem
echo "reading the default ossec.conf from $IMAGE ..."
docker run --rm --entrypoint cat "$IMAGE" /var/ossec/etc/ossec.conf > build/siem/ossec.default.conf
python3 - <<'PY'
from pathlib import Path
src = Path("build/siem/ossec.default.conf").read_text()
block = """
  <!-- AegisCloud: raw CloudTrail records mirrored by the detector (detector mirror option) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/aegis/events/*.jsonl</location>
  </localfile>
"""
assert "</ossec_config>" in src, "unexpected default ossec.conf: no closing tag"
assert "/var/aegis/events" not in src, "already patched"
idx = src.rindex("</ossec_config>")
Path("siem/wazuh/ossec.conf").write_text(src[:idx] + block + src[idx:])
print("wrote siem/wazuh/ossec.conf")
PY