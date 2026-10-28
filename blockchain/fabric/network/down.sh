#!/usr/bin/env bash
# Tear down the Fabric test-network and the CCAAS chaincode container.
#
# The chaincode container is removed first: stopping the network while the peer
# still holds a chaincode connection produces reconnect noise in the peer log.
# ./network.sh down also deletes channel artifacts and docker volumes, so each
# run starts from a clean ledger.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/version-lock.env"

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-${BLOCKCHAIN_DIR}/third_party/fabric-samples}"
NETWORK_DIR="${NETWORK_DIR:-${FABRIC_SAMPLES_DIR}/test-network}"

CC_NAME="${CC_NAME:-c5bc}"
CC_IMAGE="${CC_IMAGE:-c5bc-ccaas:${FABRIC_VERSION}}"
CC_CONTAINER_NAME="${CC_NAME}-ccaas"

REMOVE_IMAGE=0
for arg in "$@"; do
  case "$arg" in
    --remove-image) REMOVE_IMAGE=1 ;;
    -h|--help)      sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[down] %s\n' "$*"; }
warn() { printf '[down][WARN] %s\n' "$*" >&2; }

command -v docker >/dev/null 2>&1 || { warn "docker not found; nothing to tear down"; exit 0; }

if docker ps -a --format '{{.Names}}' | grep -qx "$CC_CONTAINER_NAME"; then
  log "removing chaincode container: $CC_CONTAINER_NAME"
  docker rm -f "$CC_CONTAINER_NAME" >/dev/null
else
  log "chaincode container not present: $CC_CONTAINER_NAME"
fi

if [[ -d "$NETWORK_DIR" ]]; then
  log "== network.sh down =="
  ( cd "$NETWORK_DIR" && ./network.sh down )
else
  warn "test-network not found: $NETWORK_DIR (skipping network.sh down)"
fi

if [[ "$REMOVE_IMAGE" == "1" ]]; then
  if docker image inspect "$CC_IMAGE" >/dev/null 2>&1; then
    log "removing image: $CC_IMAGE"
    docker rmi -f "$CC_IMAGE" >/dev/null
  fi
fi

log "done"
