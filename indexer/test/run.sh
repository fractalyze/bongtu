#!/usr/bin/env bash
# bongtu indexer conformance gate (SPEC §6b DoD-4).
#
# Starts a local anvil, deploys a fresh B=16 pool + runs the full scenario
# (deposit -> disburse(16) -> transfer -> withdraw -> tampered disburse),
# ingests it with the indexer, and asserts: mirror.root == contract.root +
# nextLeafIndex match at head; /path/:i folds to the head root; /events feed
# trial-decrypts to real leaves with correct leafIndex annotations;
# disclosureHash passes for the honest disburse and ALARMS "mismatch" on the
# tampered one. (§6b v2 removes plain disburse(), so "withheld" is unreachable.)
#
#   cd indexer && npm test        # (== bash test/run.sh) exits 0 iff all pass
#
# anvil runs in the background and is trap-killed on exit (no GPU/ETH; CPU proofs
# against circuits/out zkeys, same as deploy/e2e_m0.sh).
set -uo pipefail

cd "$(dirname "$0")/.."          # indexer/
INDEXER="$(pwd)"
ROOT="$(cd .. && pwd)"           # repo root

NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
PORT="${INDEXER_E2E_PORT:-8552}"
export E2E_RPC="http://127.0.0.1:${PORT}"

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- preflight: contract build + proving artifacts present -------------------
echo "== preflight: forge build + zkey/wasm presence =="
( cd "$ROOT/contracts" && "$FORGE" build >/dev/null ) || fail "forge build failed"
for n in deposit disburse transfer withdraw; do
  [ -f "$ROOT/circuits/out/${n}.zkey" ] || fail "missing circuits/out/${n}.zkey (run: cd circuits && bash prove_all.sh)"
  [ -f "$ROOT/circuits/out/${n}_js/${n}.wasm" ] || fail "missing circuits/out/${n}_js/${n}.wasm"
done

# --- start anvil (background) + trap-kill ------------------------------------
ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --silent >"$ANVIL_LOG" 2>&1 &
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
  if curl -s -X POST "$E2E_RPC" -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -q result; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || { cat "$ANVIL_LOG"; fail "anvil did not become ready on :$PORT"; }

# --- run the conformance test -----------------------------------------------
echo "== running indexer conformance test =="
RPC="$E2E_RPC" "$NODE" --max-old-space-size=16000 --import tsx "$INDEXER/test/indexer.test.ts"
RC=$?

echo ""
if [ "$RC" -eq 0 ]; then echo "INDEXER GATE: PASS"; else echo "INDEXER GATE: FAIL (rc=$RC)"; fi
exit "$RC"
