#!/usr/bin/env bash
# bongtu M1 Unit U6 — deployment pipeline on a local Foundry node (docs/milestone-m1.md Done#2).
#
# Deploys the FULL production B=256 stack (Poseidon-v1 + the 4 real Groth16
# verifiers incl. Disburse256 + BongtuPool(B=256) + mock kKRW) to a fresh local
# anvil via `forge script Deploy --broadcast`, records the addresses, then runs a
# SMOKE step (`forge script Smoke --broadcast`) that does a REAL deposit against
# the DEPLOYED pool and asserts it advanced + reads back the expected config.
#
#   cd bongtu && bash deploy/deploy_local.sh    # exits 0 iff deploy + smoke pass
#
# GIWA Sepolia is the SAME two scripts with a different env (RPC + funded key +
# Blockscout --verify) — see deploy/README.md. Starts anvil in the background and
# KILLS it on exit (trap); tracks the PID so nothing leaks.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${DEPLOY_PORT:-8550}"
RPC="${RPC:-http://127.0.0.1:${PORT}}"
CHAINID="${CHAINID:-31337}" # anvil default

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- preflight: contracts build --------------------------------------------
echo "== preflight: forge build =="
( cd contracts && "$FORGE" build >/dev/null ) || fail "forge build failed"

# --- start anvil (background) + trap-kill ----------------------------------
ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --chain-id "$CHAINID" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
cleanup() {
  [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null
  wait "$ANVIL_PID" 2>/dev/null
  rm -f "$ANVIL_LOG"
}
trap cleanup EXIT INT TERM
echo "== anvil started (pid $ANVIL_PID) on :$PORT (chainId $CHAINID) =="

READY=0
for _ in $(seq 1 50); do
  if curl -s -X POST "$RPC" -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -q result; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || { cat "$ANVIL_LOG"; fail "anvil did not become ready on :$PORT"; }

# Deployer key/addr default to anvil account 0; DEPLOYER_KEY overrides for GIWA.
export DEPLOYER_KEY="${DEPLOYER_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# --- 1) deploy the full B=256 stack (broadcast) ----------------------------
echo ""
echo "== forge script Deploy --broadcast =="
( cd contracts && "$FORGE" script ../deploy/Deploy.s.sol:Deploy \
    --rpc-url "$RPC" --broadcast --skip-simulation ) || fail "deploy script failed"

ADDR="deploy/addresses.${CHAINID}.json"
[ -f "$ADDR" ] || fail "missing $ADDR (deploy did not record addresses)"
echo ""
echo "== recorded addresses ($ADDR) =="
cat "$ADDR"

POOL=$(python3 -c "import json;print(json.load(open('$ADDR'))['pool'])")
TOKEN=$(python3 -c "import json;print(json.load(open('$ADDR'))['token'])")

# --- 2) live getter reads via cast (human-readable liveness proof) ---------
echo ""
echo "== cast getter reads against the DEPLOYED pool ($POOL) =="
B=$("$CAST" call "$POOL" "B()(uint256)" --rpc-url "$RPC")
OWNER=$("$CAST" call "$POOL" "owner()(address)" --rpc-url "$RPC")
echo "B()               = $B"
echo "owner()           = $OWNER"
echo "currentArbiterKey = $("$CAST" call "$POOL" "currentArbiterKey()(uint256,uint256)" --rpc-url "$RPC" | tr '\n' ' ')"
echo "nextLeafIndex()   = $("$CAST" call "$POOL" "nextLeafIndex()(uint256)" --rpc-url "$RPC")"
[ "$B" = "256" ] || fail "deployed pool B() != 256 (got $B)"

# --- 3) SMOKE: real deposit against the deployed pool (broadcast) -----------
echo ""
echo "== forge script Smoke --broadcast (real deposit vs DEPLOYED pool) =="
( cd contracts && "$FORGE" script ../deploy/Smoke.s.sol:Smoke \
    --rpc-url "$RPC" --broadcast --skip-simulation ) || fail "smoke script failed"

NLI=$("$CAST" call "$POOL" "nextLeafIndex()(uint256)" --rpc-url "$RPC")
echo "nextLeafIndex() after smoke = $NLI"
[ "$NLI" = "2" ] || fail "smoke deposit did not advance nextLeafIndex to 2 (got $NLI)"

echo ""
echo "U6 DoD GATE: PASS  (B=256 stack deployed + smoke deposit live on the node)"
