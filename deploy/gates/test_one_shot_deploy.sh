#!/usr/bin/env bash
# bongtu — the one-shot deploy drill.
#
# Boots a scratch anvil, runs `Deploy.s.sol` against it, and cast-verifies that
# the pool came up in its COMPLETE production shape from a single transaction —
# no follow-up step, nothing left to wire:
#   - B() == 256
#   - all six verifier getters non-zero (deposit, withdraw, disburse, transfer,
#     transfer10, transfer10x2)
#   - the Initializable version slot (ERC-7201) reads 1, so `initialize` is the
#     only initializer that has ever run and a future reinitializer(n>=2) payload
#     is still available
#   - currentEpoch() == 0 — exactly one arbiter epoch, minted by initialize
#
#   cd bongtu && bash deploy/gates/test_one_shot_deploy.sh   # exits 0 iff all pass
#
# NOTE: rewrites deploy/addresses.31337.json (scratch record). Kills the anvil on
# exit.
# No errexit — every check below asserts explicitly via `fail`, and the sibling
# anvil gates (deploy_local.sh, e2e_m0.sh) are written the same way. It also
# matters for `cleanup`: under errexit a failing `kill` aborts the EXIT trap
# itself, leaking the mktemp log and overriding the script's exit status.
set -uo pipefail

cd "$(dirname "$0")/../.."   # deploy/gates -> repo root

FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${DEPLOY_DRILL_PORT:-8561}"
RPC="http://127.0.0.1:${PORT}"
CHAINID=31337
ADDR="deploy/addresses.${CHAINID}.json"
ZERO=0x0000000000000000000000000000000000000000
# Initializable's ERC-7201 storage slot; low 8 bytes = uint64 _initialized.
INIT_SLOT=0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00

fail() { echo "FATAL: $*" >&2; exit 1; }

echo "== preflight: forge build =="
( cd contracts && "$FORGE" build >/dev/null ) || fail "forge build failed"

ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --chain-id "$CHAINID" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
cleanup() {
  if [ -n "${ANVIL_PID:-}" ]; then
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true
  fi
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
  ( cd contracts && "$FORGE" script "../deploy/forge/$2" \
      --rpc-url "$RPC" --broadcast --skip-simulation ) || fail "$1 failed"
}

version_slot() { # version_slot <pool-addr>
  local raw
  raw=$("$CAST" storage "$1" "$INIT_SLOT" --rpc-url "$RPC")
  # low 8 bytes of the word = uint64 _initialized
  echo $(( 16#${raw: -16} ))
}

verifier() { # verifier <pool-addr> <getter>
  "$CAST" call "$1" "$2()(address)" --rpc-url "$RPC"
}

step "Deploy" Deploy.s.sol:Deploy

POOL=$(python3 -c "import json;print(json.load(open('$ADDR'))['pool'])")
echo ""
echo "== cast verification (pool $POOL) =="

# --- 1) batch size ----------------------------------------------------------
B=$("$CAST" call "$POOL" "B()(uint256)" --rpc-url "$RPC")
echo "B()                   = $B"
[ "$B" = "256" ] || fail "B() != 256 (got $B)"

# --- 2) all six verifiers wired --------------------------------------------
for g in depositVerifier withdrawVerifier disburseVerifier transferVerifier \
         transfer10Verifier transfer10x2Verifier; do
  V=$(verifier "$POOL" "$g")
  printf '%-22s= %s\n' "$g()" "$V"
  [ "${V,,}" != "$ZERO" ] || fail "$g() is zero — initialize did not wire every verifier"
  REC=$(python3 -c "import json;print(json.load(open('$ADDR'))['$g'])") \
    || fail "addresses record has no $g"
  [ "${REC,,}" = "${V,,}" ] || fail "recorded $g ($REC) != on-chain ($V)"
done

# --- 3) the initializer ran exactly once, and nothing after it --------------
VER=$(version_slot "$POOL")
echo "Initializable version = $VER"
[ "$VER" = "1" ] || fail "Initializable version slot != 1 (got $VER)"

# --- 4) exactly one arbiter epoch ------------------------------------------
EPOCH=$("$CAST" call "$POOL" "currentEpoch()(uint256)" --rpc-url "$RPC")
echo "currentEpoch()        = $EPOCH"
[ "$EPOCH" = "0" ] || fail "currentEpoch() != 0 (got $EPOCH) — a second epoch was minted"

echo ""
echo "ONE-SHOT DEPLOY DRILL: PASS  (B=256, six verifiers wired, initializer version 1, single arbiter epoch)"
