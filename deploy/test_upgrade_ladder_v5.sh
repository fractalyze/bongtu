#!/usr/bin/env bash
# bongtu — full upgrade-ladder drill for the V5 (transfer10x2) migration.
#
# Boots a scratch anvil and walks it through EXACTLY the ladder the live GIWA
# pool took: Deploy (V1) -> UpgradePq (V2) -> UpgradeSelfSend (V3) ->
# UpgradeTransfer10 (V4) -> UpgradeTransfer10x2 (V5), each as
# `forge script --broadcast --skip-simulation` with the anvil dev key. Then
# cast-verifies the end state:
#   - pool B() == 256
#   - transfer10x2Verifier() != 0
#   - Initializable version slot (ERC-7201) == 5
# and runs the pre-flight NEGATIVE check: a fresh V1-only pool (Deploy re-run
# on the same anvil rewrites addresses.31337.json to a new pool) must make
# UpgradeTransfer10x2 REVERT in pre-flight ("pool is pre-V4"), before any
# broadcast.
#
#   cd bongtu && bash deploy/test_upgrade_ladder_v5.sh   # exits 0 iff all pass
#
# NOTE: rewrites deploy/addresses.31337.json (scratch record; the drill's
# whole point is exercising the AddressBook merge). Kills the anvil on exit.
set -uo pipefail

cd "$(dirname "$0")/.."

FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${LADDER_PORT:-8561}"
RPC="http://127.0.0.1:${PORT}"
CHAINID=31337
ADDR="deploy/addresses.${CHAINID}.json"
# Initializable's ERC-7201 storage slot; low 8 bytes = uint64 _initialized.
INIT_SLOT=0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00

fail() { echo "FATAL: $*" >&2; exit 1; }

echo "== preflight: forge build =="
( cd contracts && "$FORGE" build >/dev/null ) || fail "forge build failed"

ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --chain-id "$CHAINID" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
cleanup() {
  [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null
  wait "$ANVIL_PID" 2>/dev/null
  rm -f "$ANVIL_LOG"
}
trap cleanup EXIT INT TERM
echo "== anvil started (pid $ANVIL_PID) on :$PORT =="

READY=0
for _ in $(seq 1 50); do
  if curl -s -X POST "$RPC" -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -q result; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || { cat "$ANVIL_LOG"; fail "anvil did not become ready on :$PORT"; }

export DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

step() { # step <label> <script-file:contract>
  echo ""
  echo "== forge script $2 --broadcast =="
  ( cd contracts && "$FORGE" script "../deploy/$2" \
      --rpc-url "$RPC" --broadcast --skip-simulation ) || fail "$1 failed"
}

version_slot() { # version_slot <pool-addr>
  local raw
  raw=$("$CAST" storage "$1" "$INIT_SLOT" --rpc-url "$RPC")
  # low 8 bytes of the word = uint64 _initialized
  echo $(( 16#${raw: -16} ))
}

# --- the exact ladder the live pool took ------------------------------------
step "Deploy (V1)"            Deploy.s.sol:Deploy
step "UpgradePq (V2)"         UpgradePq.s.sol:UpgradePq
step "UpgradeSelfSend (V3)"   UpgradeSelfSend.s.sol:UpgradeSelfSend
step "UpgradeTransfer10 (V4)" UpgradeTransfer10.s.sol:UpgradeTransfer10
step "UpgradeTransfer10x2 (V5)" UpgradeTransfer10x2.s.sol:UpgradeTransfer10x2

# --- cast verification of the ladder's end state ----------------------------
POOL=$(python3 -c "import json;print(json.load(open('$ADDR'))['pool'])")
echo ""
echo "== cast verification (pool $POOL) =="
B=$("$CAST" call "$POOL" "B()(uint256)" --rpc-url "$RPC")
TV10X2=$("$CAST" call "$POOL" "transfer10x2Verifier()(address)" --rpc-url "$RPC")
VER=$(version_slot "$POOL")
echo "B()                    = $B"
echo "transfer10x2Verifier() = $TV10X2"
echo "Initializable version  = $VER"
[ "$B" = "256" ] || fail "B() != 256 (got $B)"
[ "$TV10X2" != "0x0000000000000000000000000000000000000000" ] || fail "transfer10x2Verifier is zero"
[ "$VER" = "5" ] || fail "Initializable version slot != 5 (got $VER)"
REC10X2=$(python3 -c "import json;print(json.load(open('$ADDR'))['transfer10x2Verifier'])") \
  || fail "addresses record has no transfer10x2Verifier after V5"
[ "${REC10X2,,}" = "${TV10X2,,}" ] || fail "recorded transfer10x2Verifier ($REC10X2) != on-chain ($TV10X2)"

# --- pre-flight NEGATIVE: V5 script vs a fresh V1-only pool must REVERT -----
echo ""
echo "== negative: UpgradeTransfer10x2 against a fresh V1-only pool =="
step "Deploy (fresh V1 pool)" Deploy.s.sol:Deploy
FRESH=$(python3 -c "import json;print(json.load(open('$ADDR'))['pool'])")
[ "$FRESH" != "$POOL" ] || fail "re-deploy did not produce a fresh pool"
NEG_LOG="$(mktemp)"
if ( cd contracts && "$FORGE" script ../deploy/UpgradeTransfer10x2.s.sol:UpgradeTransfer10x2 \
      --rpc-url "$RPC" --broadcast --skip-simulation ) >"$NEG_LOG" 2>&1; then
  cat "$NEG_LOG"; rm -f "$NEG_LOG"
  fail "UpgradeTransfer10x2 SUCCEEDED against a V1-only pool (pre-flight hole)"
fi
grep -q "pool is pre-V4: run UpgradeTransfer10 first" "$NEG_LOG" \
  || { cat "$NEG_LOG"; rm -f "$NEG_LOG"; fail "reverted, but not with the pre-flight sentence"; }
echo "pre-flight refused the V1-only pool: 'pool is pre-V4: run UpgradeTransfer10 first'"
rm -f "$NEG_LOG"

echo ""
echo "V5 LADDER DRILL: PASS  (V1->V2->V3->V4->V5, B=256, transfer10x2Verifier set, version slot 5, negative pre-flight OK)"
