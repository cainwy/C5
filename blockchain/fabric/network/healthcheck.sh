#!/usr/bin/env bash
# Post-deployment functional gate: query the chaincode profiles and assert that
# no secret material is exposed on chain.
#
#   C5Contract:C5ChaincodeProfile       -> pk_in_chaincode must be false
#   SchemeAContract:SchemeAChaincodeProfile -> plaintext_inputs must be false
#
# The C5 profile is additionally checked against the canonical artifact values
# (constraints=891908, maskctx_len=507).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/version-lock.env"

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-${BLOCKCHAIN_DIR}/third_party/fabric-samples}"
NETWORK_DIR="${NETWORK_DIR:-${FABRIC_SAMPLES_DIR}/test-network}"
CC_NAME="${CC_NAME:-c5bc}"
CHANNEL="${CHANNEL:-$CHANNEL_NAME}"
ORG="${ORG:-1}"

log()  { printf '[health] %s\n' "$*"; }
fail() { printf '[health][FAIL] %s\n' "$*" >&2; exit 1; }

[[ -d "$NETWORK_DIR" ]] || fail "test-network not found: $NETWORK_DIR"
[[ -f "${NETWORK_DIR}/scripts/envVar.sh" ]] || fail "envVar.sh not found under $NETWORK_DIR/scripts"

export PATH="${FABRIC_SAMPLES_DIR}/bin:${PATH}"
export FABRIC_CFG_PATH="${FABRIC_SAMPLES_DIR}/config"
command -v peer >/dev/null 2>&1 || fail "peer CLI not found in ${FABRIC_SAMPLES_DIR}/bin"

export TEST_NETWORK_HOME="${NETWORK_DIR}"
# envVar.sh is not nounset-safe, and this script runs with set -euo pipefail.
set +u
# shellcheck source=/dev/null
source "${NETWORK_DIR}/scripts/envVar.sh"
set -u
export VERBOSE="${VERBOSE:-false}"
export OVERRIDE_ORG="${OVERRIDE_ORG:-}"
no_u() { set +u; "$@"; local rc=$?; set -u; return $rc; }
no_u setGlobals "$ORG"
log "target peer = ${CORE_PEER_ADDRESS} (msp=${CORE_PEER_LOCALMSPID})"

query_profile() {
  # $1 primary chaincode function name, $2 fallback name
  local primary="$1" fallback="$2" out
  if out="$(peer chaincode query -C "$CHANNEL" -n "$CC_NAME" \
              -c "$(printf '{"function":"%s","Args":[]}' "$primary")" 2>/dev/null)"; then
    printf '%s\n' "$out"; return 0
  fi
  printf '[health][WARN] primary contract name %s failed; retrying %s\n' "$primary" "$fallback" >&2
  peer chaincode query -C "$CHANNEL" -n "$CC_NAME" \
    -c "$(printf '{"function":"%s","Args":[]}' "$fallback")"
}

assert_false() {
  # $1 JSON text, $2 field name, $3 context
  # jq's `//` operator treats false as empty, so has() is used to distinguish a
  # missing field from a legitimate false value.
  local out
  if ! out="$(printf '%s' "$1" | jq -r --arg k "$2" 'if has($k) then (.[$k]|tostring) else "MISSING" end')"; then
    fail "$3: jq failed on profile JSON: $1"
  fi
  if [[ "$out" == "false" ]]; then
    log "assert ok: \"$2\": false ($3)"
  else
    fail "$3: expected \"$2\": false, got: $out (raw: $1)"
  fi
}

log "== C5Contract:C5ChaincodeProfile =="
C5_JSON="$(query_profile "C5Contract:C5ChaincodeProfile" "C5:C5ChaincodeProfile")"
printf '%s\n' "$C5_JSON"
assert_false "$C5_JSON" "pk_in_chaincode" "C5 chaincode profile"
printf '%s' "$C5_JSON" | grep -qF '"constraints":891908' || fail "C5 profile is not canonical (expected constraints=891908): $C5_JSON"
printf '%s' "$C5_JSON" | grep -qF '"maskctx_len":507' || fail "C5 profile is not canonical (expected maskctx_len=507): $C5_JSON"

log "== SchemeAContract:SchemeAChaincodeProfile =="
SA_JSON="$(query_profile "SchemeAContract:SchemeAChaincodeProfile" "SchemeA:SchemeAChaincodeProfile")"
printf '%s\n' "$SA_JSON"
assert_false "$SA_JSON" "plaintext_inputs" "Scheme A chaincode profile"
if printf '%s' "$SA_JSON" | grep -qF '"pk_in_chaincode"'; then
  assert_false "$SA_JSON" "pk_in_chaincode" "Scheme A chaincode profile"
fi

log "== PASS =="
log "evidence: docker run --rm ${CC_IMAGE:-c5bc-ccaas:${FABRIC_VERSION}} ls -l /opt/chaincode/artifacts/c5_l1_507"
log "evidence: docker exec ${CC_NAME}-ccaas ls -l /opt/chaincode/artifacts/c5_l1_507"
