#!/usr/bin/env bash
# Dedicated ct-free enterprise pool gate (.dev/intents/enterprise-ctfree-pool).
#
# Proves the VERIFIER_PROFILE=ctf deploy profile end to end on a scratch anvil:
# profile deploy (B=256, named record addresses.ctf.31337.json) -> wiring +
# read-back checks -> a real CPU deposit seeding the committed fixture's input
# note -> the committed REAL GPU ct-free 256 disburse settles, with the
# disclosure fold re-checked over the zeroed receiver run (deploy/gates/ctf_leg.ts
# owns the assertions). Runs BESIDE deploy_local.sh / e2e_m0.sh — the existing
# gates stay byte-stable.
#
#   cd bongtu && bash deploy/gates/ctf_pool_local.sh    # exits 0 iff every assertion holds
set -uo pipefail

cd "$(dirname "$0")/../.."   # deploy/gates -> repo root
ROOT="$(pwd)"

NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
PORT="${CTF_GATE_PORT:-8554}"
export E2E_RPC="http://127.0.0.1:${PORT}"

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- preflight: build artifacts + the CPU deposit prover inputs -------------
echo "== preflight: forge build + deposit zkey/wasm + committed ctf fixtures =="
( cd chains/evm && "$FORGE" build >/dev/null ) || fail "forge build failed"
[ -f "circuits/out/deposit.zkey" ] || fail "missing circuits/out/deposit.zkey (run: cd circuits && bash build/prove_all.sh deposit)"
[ -f "circuits/out/deposit_js/deposit.wasm" ] || fail "missing circuits/out/deposit_js/deposit.wasm"
[ -f "chains/evm/test/fixtures/disburseCtf256.calldata.json" ] || fail "missing committed disburseCtf256 calldata fixture"

# --- scratch anvil + trap-kill ----------------------------------------------
ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  curl -sf -o /dev/null -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' "$E2E_RPC" && break
  sleep 0.2
done

# --- ctf profile deploy (writes deploy/addresses.ctf.31337.json) ------------
echo "== VERIFIER_PROFILE=ctf deploy (B=256) =="
( cd chains/evm && VERIFIER_PROFILE=ctf "$FORGE" script ../../deploy/forge/Deploy.s.sol:Deploy \
    --rpc-url "$E2E_RPC" --broadcast ) >/dev/null || fail "ctf profile deploy failed"

# --- the leg (wiring, read-backs, deposit, disburse, disclosure binding) ----
"$NODE" --import tsx deploy/gates/ctf_leg.ts
RC=$?
exit $RC
