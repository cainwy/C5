#!/usr/bin/env bash
# On-chain experiments on a real Hyperledger Fabric network (Fig. 1(b) and Table 1).
#
# Run inside WSL in a single invocation, because the containers stop when the
# distro idles out:
#   wsl -e bash /mnt/e/.../实现_C5_FULL_V4.5_PAPER_RELEASE/run/fabric_onchain.sh fig1b
#   wsl -e bash /mnt/e/.../实现_C5_FULL_V4.5_PAPER_RELEASE/run/fabric_onchain.sh tab1
#
# Environment overrides:
#   FABRIC_SAMPLES_DIR  fabric-samples root
#   ONCHAIN_BIN         prebuilt linux/amd64 binary (bin/onchain_linux)
#   REPS / WARMUPS      measured / warmup repetitions
#   CHANNEL / CHAINCODE Fabric channel and chaincode name
set -u

MODE="${1:-fig1b}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$ROOT/data"
FS="${FABRIC_SAMPLES_DIR:-${ROOT}/blockchain/third_party/fabric-samples}"
BIN="${ONCHAIN_BIN:-$ROOT/bin/onchain_linux}"
ART="$ROOT/blockchain/artifacts/c5_l1_507"
REPS="${REPS:-10}"
WARMUPS="${WARMUPS:-1}"
CHANNEL="${CHANNEL:-mychannel}"
CHAINCODE="${CHAINCODE:-c5bc}"
SEED="${SEED:-$(date +%Y%m%d-%H%M%S)}"

export PATH="$FS/bin:$PATH"
export FABRIC_CFG_PATH="$FS/config"
export TEST_NETWORK_HOME="$FS/test-network"

[ -x "$BIN" ] || { echo "missing $BIN; build it with GOOS=linux GOARCH=amd64 first" >&2; exit 2; }

echo "=== start containers ==="
# Keep the distro alive: WSL2 stops the containers when no process holds the
# distro open, which otherwise looks like an immediate container exit.
docker rm -f wslkeep >/dev/null 2>&1 || true
docker run -d --name wslkeep --restart no busybox sleep 86400 >/dev/null

docker start orderer.example.com peer0.org1.example.com peer0.org2.example.com c5bc-ccaas >/dev/null 2>&1 || true
for i in $(seq 1 60); do
  n=$(docker ps --format '{{.Names}}' | grep -c -E 'orderer.example.com|peer0.org1|peer0.org2|c5bc-ccaas')
  [ "$n" -ge 4 ] && { echo "containers up after ${i}s"; break; }
  sleep 1
done
docker ps --format '{{.Names}} :: {{.Status}}' | grep -E 'ccaas|peer0|orderer'

for i in $(seq 1 60); do
  (echo >/dev/tcp/127.0.0.1/7051) >/dev/null 2>&1 && break
  sleep 1
done
sleep 30

set +u
source "$FS/test-network/scripts/envVar.sh"
setGlobals 1
set -u
for i in $(seq 1 60); do peer channel getinfo -c "$CHANNEL" >/dev/null 2>&1 && break; sleep 2; done
echo "height_before=$(peer channel getinfo -c "$CHANNEL" 2>/dev/null | sed -n 's/.*"height":\([0-9]*\).*/\1/p')"
SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

run_c5() {
  local out="$1" cfg="$2"
  "$BIN" -backend fabric -scheme c5 -configs "$cfg" -reps "$REPS" -warmups "$WARMUPS" \
    -artifacts "$ART" -samples "$FS" -channel "$CHANNEL" -chaincode "$CHAINCODE" \
    -seed "c5-$SEED-$cfg" -out "$out"
}

run_gai() {
  local out="$1" cfg="$2" bits="$3"
  "$BIN" -backend fabric -scheme schemea -configs "$cfg" -reps "$REPS" -warmups "$WARMUPS" \
    -m 2 -t 2 -sa-profile "$bits" -samples "$FS" -channel "$CHANNEL" -chaincode "$CHAINCODE" \
    -seed "gai$bits-$SEED-$cfg" -out "$out"
}

FAIL=0
GAI_PROFILES="${GAI_PROFILES:-1024 3072}"
GAI_BITS="${GAI_BITS:-3072}"
case "$MODE" in
  fig1b)
    mkdir -p "$DATA/fig1b"
    run_c5 "$DATA/fig1b/c5" "n3_f1" || FAIL=1
    for bits in $GAI_PROFILES; do
      run_gai "$DATA/fig1b/gai$bits" "n3_f1" "$bits" || FAIL=1
    done
    ;;
  tab1)
    mkdir -p "$DATA/tab1"
    run_c5 "$DATA/tab1/c5" "n3_f1,n5_f2,n9_f4" || FAIL=1
    run_gai "$DATA/tab1/gai$GAI_BITS" "n3_f1,n5_f2,n9_f4" "$GAI_BITS" || FAIL=1
    ;;
  *)
    echo "unknown mode: $MODE (want fig1b|tab1)" >&2
    exit 2
    ;;
esac

echo "=== chaincode timing log ==="
LOG="$DATA/logs/cc_timing_${MODE}_${SEED}.log"
mkdir -p "$DATA/logs"
docker logs --since "$SINCE" c5bc-ccaas > "$LOG" 2>&1 || true
echo "cc_core_timing lines: $(grep -c '"tag":"cc_core_timing"' "$LOG" 2>/dev/null || echo 0) -> $LOG"
echo "height_after=$(peer channel getinfo -c "$CHANNEL" 2>/dev/null | sed -n 's/.*"height":\([0-9]*\).*/\1/p')"

echo "FABRIC_ONCHAIN_DONE mode=$MODE fail=$FAIL"
exit "$FAIL"
