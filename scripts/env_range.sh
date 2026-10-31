# source this file:  source scripts/env_range.sh
# racct <purple|hardened|account-id> <aws args...>   e.g.  racct hardened s3 ls
_RANGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$_RANGE_ROOT/scripts/env.sh"

racct() {
  local who="$1" id
  shift
  case "$who" in
    purple)   id=555555555555 ;;
    hardened) id=$(jq -r '.hardened.account_id' "$_RANGE_ROOT/build/range/targets.json") ;;
    *)        id="$who" ;;
  esac
  AWS_ACCESS_KEY_ID="$id" aws "$@"
}