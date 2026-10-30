#!/usr/bin/env bash
# Bring up the Fabric test-network, create the channel and deploy the C5
# chaincode as a chaincode-as-a-service (CCAAS) container.
#
# Prerequisites: Docker with the compose plugin, and fabric-samples with bin/ and
# config/ already installed (see bootstrap.sh).
#
# Topology: minimal non-CouchDB (LevelDB) network,
#   ./network.sh up createChannel -c <channel>
# CouchDB adds one container per organization and therefore noise unrelated to
# the measured endorsement/ordering/commit path.
#
# Two deployment paths are supported; path 1 is the default.
#   1) Self-managed: build the chaincode image, then let fabric/ccaas/deploy.sh
#      package/install/approve/commit and start the chaincode server.
#   2) --via-network-script: hand the package to ./network.sh deployCCAAS.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${BLOCKCHAIN_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/version-lock.env"

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-${BLOCKCHAIN_DIR}/third_party/fabric-samples}"
NETWORK_DIR="${NETWORK_DIR:-${FABRIC_SAMPLES_DIR}/test-network}"
CCAAS_DIR="${BLOCKCHAIN_DIR}/fabric/ccaas"

CC_NAME="${CC_NAME:-c5bc}"
CHANNEL="${CHANNEL:-$CHANNEL_NAME}"
CC_IMAGE="${CC_IMAGE:-c5bc-ccaas:${FABRIC_VERSION}}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_SEQUENCE="${CC_SEQUENCE:-1}"
DOCKER_NETWORK="${DOCKER_NETWORK:-}"

VIA_NETWORK_SCRIPT=0
SKIP_BUILD=0
FULL_CONTEXT=0
for arg in "$@"; do
  case "$arg" in
    --via-network-script) VIA_NETWORK_SCRIPT=1 ;;
    --skip-build)         SKIP_BUILD=1 ;;
    --full-context)       FULL_CONTEXT=1 ;;
    -h|--help)            sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[up] %s\n' "$*"; }
fail() { printf '[up][FAIL] %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found"
[[ -d "$NETWORK_DIR" ]] || fail "test-network not found: $NETWORK_DIR (run bootstrap.sh first)"
[[ -x "${FABRIC_SAMPLES_DIR}/bin/peer" ]] ||
  fail "peer CLI not found: ${FABRIC_SAMPLES_DIR}/bin/peer (run bootstrap.sh)"
[[ -f "${FABRIC_SAMPLES_DIR}/config/core.yaml" ]] ||
  fail "config/core.yaml not found: ${FABRIC_SAMPLES_DIR}/config (run bootstrap.sh)"
[[ -f "${BLOCKCHAIN_DIR}/artifacts/c5_l1_507/vk.bin" ]] ||
  fail "vk.bin missing under blockchain/artifacts/c5_l1_507 (run run/setupgen.ps1)"
[[ -f "${BLOCKCHAIN_DIR}/artifacts/c5_l1_507/manifest.json" ]] ||
  fail "manifest.json missing under blockchain/artifacts/c5_l1_507"
[[ -f "$CCAAS_DIR/Dockerfile" ]] || fail "ccaas Dockerfile not found: $CCAAS_DIR/Dockerfile"

log "fabric=${FABRIC_VERSION} ca=${FABRIC_CA_VERSION} caliper=${CALIPER_VERSION} go=${GO_VERSION}"

log "== network.sh up createChannel =="
( cd "$NETWORK_DIR" && ./network.sh up createChannel -c "$CHANNEL" )

if [[ -z "$DOCKER_NETWORK" ]]; then
  DOCKER_NETWORK="$(docker network ls --format '{{.Name}}' | grep -m1 '^fabric_test$' || true)"
  [[ -n "$DOCKER_NETWORK" ]] || DOCKER_NETWORK="$(docker network ls --format '{{.Name}}' | grep -m1 '_test$' || true)"
  [[ -n "$DOCKER_NETWORK" ]] || DOCKER_NETWORK="$DOCKER_NETWORK_DEFAULT"
fi
log "docker network = $DOCKER_NETWORK"

if [[ "$SKIP_BUILD" == "1" ]]; then
  log "skip image build (--skip-build); reuse $CC_IMAGE"
else
  log "== docker build $CC_IMAGE =="
  # The default build context is the minimal tree assembled by
  # scripts/prepare_buildctx.sh: go.mod/go.sum, internal/**, the bridge and
  # chaincode packages, and artifacts/{vk.bin,manifest.json}. Using the repository
  # root would upload pk.bin (571MB), ccs.bin (53.9MB) and third_party, and risks
  # baking the proving key into the image.
  if [[ "$FULL_CONTEXT" == "1" ]]; then
    CTX="$REPO_ROOT"
    log "WARN: using the full repository root as build context (debug only)"
  elif [[ -n "${BUILD_CONTEXT:-}" ]]; then
    CTX="$BUILD_CONTEXT"
    log "using provided BUILD_CONTEXT=$CTX"
  else
    bash "${BLOCKCHAIN_DIR}/scripts/prepare_buildctx.sh"
    CTX="${BLOCKCHAIN_DIR}/third_party/buildctx"
  fi
  log "docker build -f $CCAAS_DIR/Dockerfile -t $CC_IMAGE $CTX"
  docker build -f "$CCAAS_DIR/Dockerfile" -t "$CC_IMAGE" "$CTX"
fi

CC_CONTAINER_NAME="${CC_NAME}-ccaas"
export DOCKER_NETWORK CC_NAME CHANNEL CC_VERSION CC_SEQUENCE CC_IMAGE CC_CONTAINER_NAME

if [[ "$VIA_NETWORK_SCRIPT" == "1" ]]; then
  log "== deploy.sh --prepare-only =="
  bash "$CCAAS_DIR/deploy.sh" --prepare-only
  log "== network.sh deployCCAAS =="
  ( cd "$NETWORK_DIR" && ./network.sh deployCCAAS -ccn "$CC_NAME" -ccp "$CCAAS_DIR" -c "$CHANNEL" )
else
  # deploy.sh reads every tunable from the environment; the exported variables
  # above are the complete interface.
  log "== deploy.sh (self-managed CCAAS) =="
  bash "$CCAAS_DIR/deploy.sh"
fi

log "== next =="
log "healthcheck : bash ${SCRIPT_DIR}/healthcheck.sh"
log "caliper     : cd ${BLOCKCHAIN_DIR}/caliper && npm ci && npx caliper launch manager --caliper-workspace . --caliper-benchconfig benchmarks/benchmark-verifyC5.yaml --caliper-networkconfig networks/network-local.yaml"
log "teardown    : bash ${SCRIPT_DIR}/down.sh"
