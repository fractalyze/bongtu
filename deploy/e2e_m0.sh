#!/usr/bin/env bash
# bongtu M0 Unit U4 — the M0 Definition of Done (.dev/milestone-m0.md Done#4, spec §5/§10b).
#
# Full cross-circuit spend cycle on a LIVE anvil with REAL Groth16 proofs and a
# GENUINE recipient trial-decrypt:
#   deposit -> disburse(1x16) -> trial-decrypt a batch note -> transfer(real
#   batch-note spend + padded enabled=0) -> withdraw -> self-transfer (§11-8
#   v1.1), asserting contract.root == ImtTree oracle root after every insert,
#   the recipient note recovered from ciphertext (not memory), and end-to-end
#   value conserved.
#
#   cd bongtu && bash deploy/e2e_m0.sh    # exits 0 iff every assertion holds
#
# Starts a local anvil in the background and KILLS it on exit (trap). Proving is
# CPU snarkjs against the committed circuits/out zkeys (their verification keys
# match the committed verifiers). .zkey/.wtns/.r1cs/out stay gitignored.
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# Overridable toolchain: prefer PATH, fall back to the known dev locations, so
# the DoD gate is reproducible on a fresh checkout / CI, not just this machine.
NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
PORT="${E2E_PORT:-8549}"
export E2E_RPC="http://127.0.0.1:${PORT}"

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- preflight: build artifacts + proving inputs exist ----------------------
echo "== preflight: forge build + zkey/wasm presence =="
( cd contracts && "$FORGE" build >/dev/null ) || fail "forge build failed"
for n in deposit disburse transfer withdraw; do
  [ -f "circuits/out/${n}.zkey" ] || fail "missing circuits/out/${n}.zkey (run: cd circuits && bash prove_all.sh)"
  [ -f "circuits/out/${n}_js/${n}.wasm" ] || fail "missing circuits/out/${n}_js/${n}.wasm (run prove_all.sh)"
done

# --- start anvil (background) + trap-kill -----------------------------------
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

# wait until the RPC answers
READY=0
for _ in $(seq 1 50); do
  if curl -s -X POST "$E2E_RPC" -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -q result; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || { cat "$ANVIL_LOG"; fail "anvil did not become ready on :$PORT"; }

# --- drive the cycle --------------------------------------------------------
echo "== running e2e orchestrator =="
"$NODE" --max-old-space-size=16000 --import tsx deploy/e2e_orchestrator.ts
RC=$?

echo ""
if [ "$RC" -eq 0 ]; then
  echo "M0 DoD GATE: PASS"
else
  echo "M0 DoD GATE: FAIL (rc=$RC)"
fi
exit "$RC"
