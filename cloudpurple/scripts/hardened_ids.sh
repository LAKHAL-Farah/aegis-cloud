#!/usr/bin/env bash
# Writes the generated hardened account id where the hardened root can read it.
set -euo pipefail
cd "$(dirname "$0")/../.."
id=$(terraform -chdir=terraform/live/management output -json member_account_ids | jq -r '."aegis-hardened" // empty')
if [ -z "$id" ]; then
  echo "no aegis-hardened account yet: run 'make apply-management' (section 4.2)" >&2
  exit 1
fi
cat > cloudpurple/terraform/hardened/hardened.auto.tfvars <<EOF
account_name = "hardened"
accounts = {
  hardened = "$id"
}
EOF
echo "hardened account id: $id"