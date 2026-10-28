#!/usr/bin/env bash
# Check that the Fabric network and the C5 chaincode are reachable.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FS="${FABRIC_SAMPLES_DIR:-${ROOT}/blockchain/third_party/fabric-samples}"
CHANNEL="${CHANNEL:-mychannel}"
export PATH="$FS/bin:$PATH"
export FABRIC_CFG_PATH="$FS/config"
export TEST_NETWORK_HOME="$FS/test-network"

echo "--- containers ---"
docker ps --format '{{.Names}} :: {{.Status}}' | grep -E 'ccaas|peer0|orderer' || echo "none"

cd "$TEST_NETWORK_HOME"
set +u
# shellcheck source=/dev/null
source scripts/envVar.sh
setGlobals 1
set -u

echo "--- channel ---"
peer channel getinfo -c "$CHANNEL" 2>&1 | head -3

echo "--- committed chaincode ---"
peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name c5bc 2>&1 | head -5
