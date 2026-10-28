#!/usr/bin/env bash
# Assemble the minimal Docker build context for the CCAAS chaincode image.
#
# The context contains go.mod/go.sum of both modules, internal/**, the bridge and
# chaincode packages, the protocol-fidelity package, and artifacts/{vk.bin,
# manifest.json}. The proving key and the compiled constraint system are never
# copied, so they cannot leak into the image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${BLOCKCHAIN_DIR}/.." && pwd)"
OUT="${BUILD_CONTEXT:-${BLOCKCHAIN_DIR}/third_party/buildctx}"
ART="${BLOCKCHAIN_DIR}/artifacts/c5_l1_507"

log() { printf '[buildctx] %s\n' "$*"; }

rm -rf "$OUT"
mkdir -p "$OUT"

copy() {
  local src="$1" dst="$2"
  [[ -e "$REPO_ROOT/$src" ]] || { echo "[buildctx][FAIL] missing $src" >&2; exit 1; }
  mkdir -p "$OUT/$(dirname "$dst")"
  cp -R "$REPO_ROOT/$src" "$OUT/$dst"
}

copy go.mod go.mod
copy go.sum go.sum
copy blockchain/go.mod blockchain/go.mod
copy blockchain/go.sum blockchain/go.sum
copy internal internal
copy blockchain/bridge blockchain/bridge
copy blockchain/fabric/chaincode blockchain/fabric/chaincode
copy blockchain/protocol_fidelity blockchain/protocol_fidelity

mkdir -p "$OUT/blockchain/artifacts/c5_l1_507"
cp "$ART/vk.bin" "$OUT/blockchain/artifacts/c5_l1_507/vk.bin"
cp "$ART/manifest.json" "$OUT/blockchain/artifacts/c5_l1_507/manifest.json"

if [[ -e "$OUT/blockchain/artifacts/c5_l1_507/pk.bin" || -e "$OUT/blockchain/artifacts/c5_l1_507/ccs.bin" ]]; then
  echo "[buildctx][FAIL] proving key or constraint system present in the build context" >&2
  exit 1
fi

log "context=$OUT"
du -sh "$OUT" 2>/dev/null || true
