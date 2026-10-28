#!/usr/bin/env bash
# Pre-flight check for the Fabric deployment: tool availability, artifact hashes,
# and availability of fabric-samples.
#
# The script does not pull images or run npm install. Missing Docker or Go is
# reported as an error unless --allow-missing is given, in which case only the
# artifact hashes are verified.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BLOCKCHAIN_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
REPO_ROOT="$(cd "${BLOCKCHAIN_DIR}/.." && pwd)"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/version-lock.env"

FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-${BLOCKCHAIN_DIR}/third_party/fabric-samples}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${BLOCKCHAIN_DIR}/artifacts/c5_l1_507}"
MANIFEST="${ARTIFACT_DIR}/manifest.json"

ALLOW_MISSING=0
NO_CLONE=0
for arg in "$@"; do
  case "$arg" in
    --allow-missing) ALLOW_MISSING=1 ;;
    --no-clone)      NO_CLONE=1 ;;
    -h|--help)       sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

log()  { printf '[bootstrap] %s\n' "$*"; }
warn() { printf '[bootstrap][WARN] %s\n' "$*" >&2; }
fail() { printf '[bootstrap][FAIL] %s\n' "$*" >&2; exit 1; }

MISSING_TOOLS=()
have() { command -v "$1" >/dev/null 2>&1; }

check_tool() {
  # $1 executable, $2 version command, $3 hard requirement (1/0)
  local name="$1" vercmd="$2" hard="$3"
  if have "$name"; then
    log "found ${name}: $(${vercmd} 2>&1 | head -n 1)"
  else
    warn "missing tool: ${name}"
    MISSING_TOOLS+=("$name")
    if [[ "$hard" == "1" && "$ALLOW_MISSING" != "1" ]]; then
      fail "${name} is required for the Fabric path; re-run with --allow-missing to verify artifacts only"
    fi
  fi
}

log "== tooling =="
check_tool jq        "jq --version" 1
check_tool sha256sum "true"         1
check_tool node      "node --version" 0
check_tool go        "go version"     0
check_tool docker    "docker --version" 0
check_tool git       "git --version"    0

if have docker && docker compose version >/dev/null 2>&1; then
  log "found docker compose: $(docker compose version 2>&1 | head -n 1)"
elif have docker-compose; then
  log "found docker-compose (legacy): $(docker-compose --version 2>&1 | head -n 1)"
else
  warn "docker compose plugin / docker-compose not found"
  MISSING_TOOLS+=("docker-compose")
fi

log "== artifact hash verification =="
[[ -f "$MANIFEST" ]] || fail "manifest not found: $MANIFEST"

verify_one() {
  # $1 file name inside ARTIFACT_DIR, $2 manifest sha256 field, $3 required (1/0)
  local file="${ARTIFACT_DIR}/$1" field="$2" required="$3"
  local expected actual
  expected="$(jq -r --arg f "$field" '.[$f] // empty' "$MANIFEST")"
  if [[ ! -f "$file" ]]; then
    if [[ "$required" == "1" ]]; then
      fail "required artifact missing: $file"
    fi
    log "skip ${1} (not present on disk)"
    return 0
  fi
  [[ -n "$expected" ]] || fail "manifest has no ${field}; cannot verify ${1}"
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    fail "sha256 mismatch for ${1}: manifest=${expected} actual=${actual}"
  fi
  log "ok ${1} sha256=${actual} size=$(wc -c <"$file" | tr -d ' ')B"
}

verify_one "vk.bin"  "sha256_vk"  1
verify_one "ccs.bin" "sha256_ccs" 0
verify_one "pk.bin"  "sha256_pk"  0

log "profile_id=$(jq -r '.profile_id' "$MANIFEST") L=$(jq -r '.L' "$MANIFEST") maskctx_len=$(jq -r '.maskctx_len' "$MANIFEST") constraints=$(jq -r '.constraints' "$MANIFEST")"
if [[ "$(jq -r '.constraints' "$MANIFEST")" != "891908" || \
      "$(jq -r '.L' "$MANIFEST")" != "1" || \
      "$(jq -r '.maskctx_len' "$MANIFEST")" != "507" ]]; then
  fail "non-canonical artifact profile (expected L=1, maskctx_len=507, constraints=891908)"
fi

log "== fabric-samples =="
if [[ -d "$FABRIC_SAMPLES_DIR" ]]; then
  log "reuse existing fabric-samples: $FABRIC_SAMPLES_DIR"
elif [[ "$NO_CLONE" == "1" ]]; then
  warn "fabric-samples missing and --no-clone given: $FABRIC_SAMPLES_DIR"
else
  mkdir -p "$(dirname "$FABRIC_SAMPLES_DIR")"
  log "cloning hyperledger/fabric-samples @ v${FABRIC_VERSION} (depth 1) -> $FABRIC_SAMPLES_DIR"
  if ! git clone --depth 1 --branch "v${FABRIC_VERSION}" \
        https://github.com/hyperledger/fabric-samples.git "$FABRIC_SAMPLES_DIR"; then
    fail "git clone failed. Clone fabric-samples manually and re-run with --no-clone"
  fi
  log "checkout: $(git -C "$FABRIC_SAMPLES_DIR" rev-parse --short HEAD)"
  warn "test-network also needs bin/ and config/: run install-fabric.sh binary in that directory"
fi

log "== summary =="
log "REPO_ROOT         = $REPO_ROOT"
log "BLOCKCHAIN_DIR    = $BLOCKCHAIN_DIR"
log "ARTIFACT_DIR      = $ARTIFACT_DIR"
log "FABRIC_SAMPLES_DIR= $FABRIC_SAMPLES_DIR"
if [[ "${#MISSING_TOOLS[@]}" -gt 0 ]]; then
  warn "missing tools: ${MISSING_TOOLS[*]}"
fi
log "done"
