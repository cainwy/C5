#!/usr/bin/env bash
# Package, install, approve and commit the C5 chaincode as a CCAAS service, then
# start its container.
#
# Steps: render connection.json, build metadata, assemble the package, install it
# on both organizations, approve it for both organizations, check commit
# readiness, commit, query the committed definition, and start the server.
#
# CHAINCODE_ID is only known after the package is assembled, so it is injected as
# a container environment variable rather than written into connection.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${BLOCKCHAIN_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${BLOCKCHAIN_DIR}/fabric/network/version-lock.env"

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-${BLOCKCHAIN_DIR}/third_party/fabric-samples}"
NETWORK_DIR="${NETWORK_DIR:-${FABRIC_SAMPLES_DIR}/test-network}"

CC_NAME="${CC_NAME:-c5bc}"
CHANNEL="${CHANNEL:-$CHANNEL_NAME}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
CC_IMAGE="${CC_IMAGE:-c5bc-ccaas:${FABRIC_VERSION}}"
CC_CONTAINER_NAME="${CC_NAME}-ccaas"
DOCKER_NETWORK="${DOCKER_NETWORK:-fabric_test}"
CC_ADDRESS="${CC_ADDRESS:-${CC_CONTAINER_NAME}:${CCAAS_SERVER_PORT}}"
DIAL_TIMEOUT="${DIAL_TIMEOUT:-10s}"
SIGNATURE_POLICY="${SIGNATURE_POLICY:-AND('Org1MSP.peer','Org2MSP.peer')}"

BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build}"
PKGSRC_DIR="${BUILD_DIR}/pkgsrc"
PACKAGE_DIR="${BUILD_DIR}/package"
PACKAGE_FILE="${PACKAGE_DIR}/${CC_NAME}.tar.gz"
CC_LABEL="${CC_NAME}_${CC_VERSION}"

PREPARE_ONLY=0
NO_START=0
for arg in "$@"; do
  case "$arg" in
    --prepare-only) PREPARE_ONLY=1 ;;
    --no-start)     NO_START=1 ;;
    -h|--help)      sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[deploy] %s\n' "$*"; }
fail() { printf '[deploy][FAIL] %s\n' "$*" >&2; exit 1; }

log "== render connection.json (address=${CC_ADDRESS}, dial_timeout=${DIAL_TIMEOUT}) =="
mkdir -p "$PKGSRC_DIR"
# tls_required=false matches shim.TLSProperties{Disabled:true} in cmd/cc/main.go.
sed -e "s|@@CC_ADDRESS@@|${CC_ADDRESS}|g" \
    -e "s|@@DIAL_TIMEOUT@@|${DIAL_TIMEOUT}|g" \
    "${SCRIPT_DIR}/connection.json.tmpl" > "${PKGSRC_DIR}/connection.json"

cat > "${PKGSRC_DIR}/metadata.json" <<EOF
{
  "type": "ccaas",
  "label": "${CC_LABEL}"
}
EOF

if [[ "$PREPARE_ONLY" == "1" || "${VIA_NETWORK_SCRIPT:-0}" == "1" ]]; then
  cp "${PKGSRC_DIR}/connection.json" "${SCRIPT_DIR}/connection.json"
  log "copied connection.json -> ${SCRIPT_DIR}/connection.json (for network.sh deployCCAAS -ccp)"
fi

if [[ "$PREPARE_ONLY" == "1" ]]; then
  log "prepare-only: skipping package/install/approve/commit/run"
  exit 0
fi

command -v peer >/dev/null 2>&1 || fail "peer CLI not found (export PATH=${FABRIC_SAMPLES_DIR}/bin:\$PATH)"
[[ -f "${NETWORK_DIR}/scripts/envVar.sh" ]] || fail "envVar.sh not found: ${NETWORK_DIR}/scripts/envVar.sh"
export PATH="${FABRIC_SAMPLES_DIR}/bin:${PATH}"
export FABRIC_CFG_PATH="${FABRIC_SAMPLES_DIR}/config"
# envVar.sh locates scripts/utils.sh through TEST_NETWORK_HOME, whose default is
# $PWD; this script runs from blockchain/, so it must be exported explicitly.
export TEST_NETWORK_HOME="${NETWORK_DIR}"
# envVar.sh and utils.sh are not nounset-safe, so -u is disabled around them.
set +u
# shellcheck source=/dev/null
source "${NETWORK_DIR}/scripts/envVar.sh"
set -u
export VERBOSE="${VERBOSE:-false}"
export OVERRIDE_ORG="${OVERRIDE_ORG:-}"

no_u() { set +u; "$@"; local rc=$?; set -u; return $rc; }
export ORDERER_CA="${NETWORK_DIR}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
ORG1_TLS_CA="${NETWORK_DIR}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
ORG2_TLS_CA="${NETWORK_DIR}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
[[ -f "$ORDERER_CA" ]] || fail "ORDERER_CA not found: $ORDERER_CA (is the network up?)"

# The package layout follows fabric-samples' CCAAS path: metadata.json plus
# code.tar.gz that contains only connection.json. `peer lifecycle chaincode
# package --lang ccaas` imposes version-dependent layout requirements, so the
# archive is assembled directly and the package id is computed from its contents.
log "== build CCAAS package =="
PKG_TMP="$(mktemp -d -t c5bc-pkg.XXXXXXXX)"
mkdir -p "${PKG_TMP}/src" "${PKG_TMP}/pkg"
cp "${PKGSRC_DIR}/connection.json" "${PKG_TMP}/src/connection.json"
cat > "${PKG_TMP}/pkg/metadata.json" <<EOF
{
  "type": "ccaas",
  "label": "${CC_LABEL}"
}
EOF
tar -C "${PKG_TMP}/src" -czf "${PKG_TMP}/pkg/code.tar.gz" .
mkdir -p "$PACKAGE_DIR"
tar -C "${PKG_TMP}/pkg" -czf "$PACKAGE_FILE" metadata.json code.tar.gz
rm -rf "$PKG_TMP"
log "package file: ${PACKAGE_FILE} ($(wc -c <"$PACKAGE_FILE" | tr -d ' ')B)"
PACKAGE_ID="$(peer lifecycle chaincode calculatepackageid "$PACKAGE_FILE")"
[[ -n "$PACKAGE_ID" ]] || fail "cannot compute package id"
log "package_id = $PACKAGE_ID"

for org in 1 2; do
  log "== install (org${org}) =="
  no_u setGlobals "$org"
  peer lifecycle chaincode install "$PACKAGE_FILE"
  # A label can map to several historical packages, so the assertion is that the
  # package id computed above appears among the installed ids.
  ALL_IDS="$(peer lifecycle chaincode queryinstalled --output json \
    | jq -r '.installed_chaincodes[].package_id')"
  printf '%s\n' "$ALL_IDS" | grep -qx "$PACKAGE_ID" \
    || fail "org${org}: freshly built package id ${PACKAGE_ID} not found in queryinstalled"
  log "org${org} package_id verified = $PACKAGE_ID"
done

for org in 1 2; do
  log "== approveformyorg (org${org}) =="
  no_u setGlobals "$org"
  peer lifecycle chaincode approveformyorg -o "localhost:${ORDERER_PORT}" \
    --ordererTLSHostnameOverride "$ORDERER_TLS_HOSTNAME" \
    --channelID "$CHANNEL" --name "$CC_NAME" \
    --version "$CC_VERSION" --package-id "$PACKAGE_ID" --sequence "$CC_SEQUENCE" \
    --signature-policy "$SIGNATURE_POLICY" \
    --tls --cafile "$ORDERER_CA"
done

log "== checkcommitreadiness =="
no_u setGlobals 1
peer lifecycle chaincode checkcommitreadiness --channelID "$CHANNEL" \
  --name "$CC_NAME" --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
  --signature-policy "$SIGNATURE_POLICY" --tls --cafile "$ORDERER_CA" --output json

log "== commit =="
peer lifecycle chaincode commit -o "localhost:${ORDERER_PORT}" \
  --ordererTLSHostnameOverride "$ORDERER_TLS_HOSTNAME" \
  --channelID "$CHANNEL" --name "$CC_NAME" \
  --version "$CC_VERSION" --sequence "$CC_SEQUENCE" \
  --signature-policy "$SIGNATURE_POLICY" \
  --peerAddresses "localhost:${PEER0_ORG1_PORT}" --tlsRootCertFiles "$ORG1_TLS_CA" \
  --peerAddresses "localhost:${PEER0_ORG2_PORT}" --tlsRootCertFiles "$ORG2_TLS_CA" \
  --tls --cafile "$ORDERER_CA"

log "== querycommitted =="
peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME" --output json

if [[ "$NO_START" == "1" ]]; then
  log "--no-start: start the chaincode server manually with at least:"
  log "  docker run -d --name ${CC_CONTAINER_NAME} --network ${DOCKER_NETWORK} \\"
  log "    -e CHAINCODE_ID=${PACKAGE_ID} -e CHAINCODE_SERVER_ADDRESS=0.0.0.0:${CCAAS_SERVER_PORT} \\"
  log "    -e C5_VK_DIR=/opt/chaincode/artifacts/c5_l1_507 ${CC_IMAGE}"
  exit 0
fi

log "== docker run ${CC_CONTAINER_NAME} =="
docker rm -f "$CC_CONTAINER_NAME" >/dev/null 2>&1 || true
# CHAINCODE_ID must equal the package id; the server address must bind 0.0.0.0 so
# peers can reach it; C5_VK_DIR is checked against the manifest on startup.
# The image contains vk.bin only, never pk.bin or ccs.bin.
docker run -d --name "$CC_CONTAINER_NAME" \
  --network "$DOCKER_NETWORK" \
  -e CHAINCODE_ID="$PACKAGE_ID" \
  -e CHAINCODE_SERVER_ADDRESS="0.0.0.0:${CCAAS_SERVER_PORT}" \
  -e C5_VK_DIR=/opt/chaincode/artifacts/c5_l1_507 \
  "$CC_IMAGE"

log "== wait for chaincode server readiness =="
READY=0
for _ in $(seq 1 30); do
  if docker logs "$CC_CONTAINER_NAME" 2>&1 | grep -q '"tag":"cc_startup"'; then
    READY=1; break
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx "$CC_CONTAINER_NAME"; then
    break
  fi
  sleep 2
done
if [[ "$READY" != "1" ]]; then
  fail "chaincode server did not report cc_startup; docker logs:
$(docker logs "$CC_CONTAINER_NAME" 2>&1 | tail -n 40)"
fi
docker logs "$CC_CONTAINER_NAME" 2>&1 | grep '"tag":"cc_startup"' | tail -n 1
log "deployed: channel=${CHANNEL} chaincode=${CC_NAME} sequence=${CC_SEQUENCE} container=${CC_CONTAINER_NAME}"
