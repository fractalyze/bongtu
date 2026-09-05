#!/usr/bin/env bash
# bongtu M0 Unit U4 — the M0 Definition of Done (.dev/milestone-m0.md Done#4, spec §5/§10b).
#
# Full cross-circuit spend cycle on a LIVE anvil with REAL Groth16 proofs and a
# GENUINE recipient trial-decrypt:
#   deposit -> disburse(1x16) -> trial-decrypt a batch note -> transfer(real
#   batch-note spend + padded enabled=0) -> withdraw -> self-transfer (§11-8
#   v1.1), asserting contract.root == ImtTree oracle root after every insert,
#   the recipient note recovered from ciphertext (not memory), and end-to-end
#   value conserved — then the portal-deposit loop (deploy/gates/portal_leg.ts:
#   factory + real indexer + sweeper runOnce), which needs the Postgres this
#   script provisions, and then the arbiter-free consumer leg
#   (deploy/gates/consumer_leg.ts: consumer-only profile deploy + the V3
#   module upgrade, CPU-proved consumer ops with disburse chunk txs, a PUBLIC
#   indexer, and self-scan discovery), which needs its own bongtu_consumer
#   database on that Postgres (E2E_CONSUMER_DATABASE_URL). No Postgres is
#   FATAL — for the portal database AND the bongtu_consumer one: both legs
#   are part of the DoD and must never be skipped silently.
#
#   cd bongtu && bash deploy/gates/e2e_m0.sh    # exits 0 iff every assertion holds
#
# Starts a local anvil in the background and KILLS it on exit (trap). Proving is
# CPU snarkjs against the committed circuits/out zkeys (their verification keys
# match the committed verifiers). .zkey/.wtns/.r1cs/out stay gitignored.
set -uo pipefail

cd "$(dirname "$0")/../.."   # deploy/gates -> repo root
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
( cd chains/evm && "$FORGE" build >/dev/null ) || fail "forge build failed"
for n in deposit disburse transfer withdraw depositPriv transferPriv withdrawPriv disbursePriv; do
  [ -f "circuits/out/${n}.zkey" ] || fail "missing circuits/out/${n}.zkey (run: cd circuits && bash build/prove_all.sh)"
  [ -f "circuits/out/${n}_js/${n}.wasm" ] || fail "missing circuits/out/${n}_js/${n}.wasm (run build/prove_all.sh)"
done

# --- start anvil (background) + trap-kill -----------------------------------
ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
PG_NAME=""
DOCKER="${DOCKER:-$(command -v docker || echo docker)}"
cleanup() {
  [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null
  wait "$ANVIL_PID" 2>/dev/null
  rm -f "$ANVIL_LOG"
  [ -n "$PG_NAME" ] && "$DOCKER" rm -f "$PG_NAME" >/dev/null 2>&1
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

# --- postgres for the portal leg (the indexer is Postgres-only) --------------
# The portal e2e leg spawns a real arbiter indexer, which needs Postgres. Honor
# an exported E2E_DATABASE_URL (CI service / dev override); otherwise spin a
# throwaway postgres:16-alpine in docker (trap-removed, same pattern as the
# indexer conformance gate). NO silent skip: the portal leg is part of the DoD,
# so "no postgres possible" is a FATAL — the orchestrator also fails on a
# missing E2E_DATABASE_URL as the belt.
if [ -z "${E2E_DATABASE_URL:-}" ]; then
  if command -v "$DOCKER" >/dev/null 2>&1 && "$DOCKER" info >/dev/null 2>&1; then
    PG_PORT="${E2E_PG_PORT:-$((22000 + (RANDOM % 20000)))}"
    PG_NAME="bongtu-m0-pg-$$"
    echo "== start throwaway postgres:16-alpine on :$PG_PORT (container $PG_NAME) =="
    "$DOCKER" run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=postgres \
      -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || fail "docker run postgres failed"
    PGREADY=0
    for _ in $(seq 1 60); do
      if "$DOCKER" exec "$PG_NAME" pg_isready -U postgres -q >/dev/null 2>&1; then PGREADY=1; break; fi
      sleep 0.5
    done
    [ "$PGREADY" = 1 ] || { "$DOCKER" logs "$PG_NAME" 2>&1 | tail -20; fail "postgres did not become ready"; }
    export E2E_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/postgres"
    # The CONSUMER leg spawns a SECOND indexer (public mode) against its own
    # pool; two indexers must never share one database (each owns its schema +
    # cursor), so it gets a dedicated database in the same container.
    "$DOCKER" exec "$PG_NAME" createdb -U postgres bongtu_consumer || fail "createdb bongtu_consumer failed"
    export E2E_CONSUMER_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/bongtu_consumer"
  else
    fail "the portal leg needs Postgres: export E2E_DATABASE_URL or make docker available (the leg is part of the DoD — no silent skip)"
  fi
fi
# Belt for an externally provisioned E2E_DATABASE_URL (CI service): the consumer
# leg needs its OWN database and must never silently skip.
[ -n "${E2E_CONSUMER_DATABASE_URL:-}" ] || \
  fail "the consumer leg needs its own Postgres database: export E2E_CONSUMER_DATABASE_URL (a different database on the same server is fine)"

# --- drive the cycle --------------------------------------------------------
echo "== running e2e orchestrator =="
"$NODE" --max-old-space-size=16000 --import tsx deploy/gates/e2e_orchestrator.ts
RC=$?

echo ""
if [ "$RC" -eq 0 ]; then
  echo "M0 DoD GATE: PASS"
else
  echo "M0 DoD GATE: FAIL (rc=$RC)"
fi
exit "$RC"
