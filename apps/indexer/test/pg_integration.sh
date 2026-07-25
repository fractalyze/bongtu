#!/usr/bin/env bash
# bongtu indexer Postgres integration gate (U-I2) — LOCAL, docker-based.
#
# Proves the Postgres store/ledger adapters end-to-end AND that a restart RESUMES
# from the block cursor instead of replaying the chain:
#
#   1. start anvil + deploy/drive the scenario (deposit → disburse(16) → transfer →
#      withdraw → tampered disburses) — the SAME cycle the conformance gate uses;
#   2. spin a throwaway postgres:16-alpine on a random host port (trap-removed);
#   3. start an ARBITER + DATABASE_URL indexer #1 → assert /head /notes /history
#      match the scenario (served from the Postgres-backed read model);
#   4. KILL indexer #1, start indexer #2 against the SAME postgres →
#        - assert its log shows "resume from block N" with N>0 (NOT a block-0 replay),
#        - assert /head /notes /history are byte-identical to indexer #1 (stable).
#   5. CRASH-IN-PERSIST-WINDOW leg (test/pg_resume.ts, fresh `crashtest` DB):
#        fault-inject a crash right before the persist COMMIT and prove the txn
#        rolls back atomically (leaves never advance past the cursor), a fresh boot
#        does NOT wedge, resume converges byte-identical to a clean run, and a
#        re-ingest over a persisted range double-counts nothing. This is the
#        BLOCKER's proof: atomic persist makes the leaves-ahead-of-cursor wedge
#        unreachable by construction.
#
# This is a LOCAL gate (docker + anvil + CPU proofs); it is deliberately NOT wired
# into the hosted CI conformance job (see apps/indexer/README.md → U-I3 covers the
# containerised CI path). Requires: docker, the forge/anvil/node toolchain, and the
# CPU proving artifacts under circuits/out (same preconditions as `npm test`).
#
#   cd apps/indexer && bash test/pg_integration.sh    # exits 0 iff every step holds
set -uo pipefail

cd "$(dirname "$0")/.."
INDEXER="$(pwd)"
ROOT="$(cd ../.. && pwd)"

NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
DOCKER="${DOCKER:-$(command -v docker || echo docker)}"

ANVIL_PORT="${PG_IT_ANVIL_PORT:-8556}"
IX1_PORT="${PG_IT_IX1_PORT:-8613}"
IX2_PORT="${PG_IT_IX2_PORT:-8614}"
PG_PORT="${PG_IT_PG_PORT:-$((20000 + (RANDOM % 20000)))}"
PG_NAME="bongtu-pg-it-$$"
export E2E_RPC="http://127.0.0.1:${ANVIL_PORT}"

FIXTURES="$(mktemp)"
ANVIL_LOG="$(mktemp)"
IX1_LOG="$(mktemp)"
IX2_LOG="$(mktemp)"
ANVIL_PID=""
IX1_PID=""
IX2_PID=""

fail() { echo "FATAL: $*" >&2; exit 1; }

cleanup() {
  [ -n "$IX1_PID" ] && kill "$IX1_PID" 2>/dev/null
  [ -n "$IX2_PID" ] && kill "$IX2_PID" 2>/dev/null
  [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null
  wait "$IX1_PID" 2>/dev/null
  wait "$IX2_PID" 2>/dev/null
  wait "$ANVIL_PID" 2>/dev/null
  "$DOCKER" rm -f "$PG_NAME" >/dev/null 2>&1
  rm -f "$FIXTURES" "$ANVIL_LOG" "$IX1_LOG" "$IX2_LOG"
}
trap cleanup EXIT INT TERM

# --- preflight ---------------------------------------------------------------
echo "== preflight: docker + forge build + zkey/wasm presence =="
command -v "$DOCKER" >/dev/null 2>&1 || fail "docker not found (this is a docker-based gate)"
"$DOCKER" info >/dev/null 2>&1 || fail "docker daemon not reachable"
( cd "$ROOT/contracts" && "$FORGE" build >/dev/null ) || fail "forge build failed"
for n in deposit disburse transfer withdraw; do
  [ -f "$ROOT/circuits/out/${n}.zkey" ] || fail "missing circuits/out/${n}.zkey (run: cd circuits && bash prove_all.sh)"
  [ -f "$ROOT/circuits/out/${n}_js/${n}.wasm" ] || fail "missing circuits/out/${n}_js/${n}.wasm"
done

# --- anvil -------------------------------------------------------------------
"$ANVIL" --port "$ANVIL_PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
echo "== anvil started (pid $ANVIL_PID) on :$ANVIL_PORT =="
READY=0
for _ in $(seq 1 50); do
  if curl -s -X POST "$E2E_RPC" -H 'content-type: application/json' \
       --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null | grep -q result; then
    READY=1; break
  fi
  sleep 0.2
done
[ "$READY" = 1 ] || { cat "$ANVIL_LOG"; fail "anvil did not become ready on :$ANVIL_PORT"; }

# --- deploy + drive the scenario (writes the fixtures the indexer reproduces) --
echo "== deploy + drive scenario (CPU proofs) =="
RPC="$E2E_RPC" "$NODE" --import tsx "$INDEXER/test/pg_scenario_setup.ts" "$FIXTURES" || fail "scenario setup failed"
readfix() { "$NODE" -e "process.stdout.write(String(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))[process.argv[2]]))" "$FIXTURES" "$1"; }
POOL_ADDR="$(readfix poolAddr)"
ARBITER_KEY="$(readfix arbiterPrivateKey)"
[ -n "$POOL_ADDR" ] || fail "no pool address in fixtures"
echo "   pool=$POOL_ADDR"

# --- throwaway postgres ------------------------------------------------------
echo "== start throwaway postgres:16-alpine on :$PG_PORT (container $PG_NAME) =="
"$DOCKER" run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=postgres \
  -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || fail "docker run postgres failed"
PGREADY=0
for _ in $(seq 1 60); do
  if "$DOCKER" exec "$PG_NAME" pg_isready -U postgres -q >/dev/null 2>&1; then PGREADY=1; break; fi
  sleep 0.5
done
[ "$PGREADY" = 1 ] || { "$DOCKER" logs "$PG_NAME" 2>&1 | tail -20; fail "postgres did not become ready"; }
export DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/postgres"

# --- shared launcher / waiters ----------------------------------------------
start_indexer() {  # $1=port  $2=logfile  -> echoes pid
  RPC="$E2E_RPC" POOL="$POOL_ADDR" AUTHORITY_KEY="$ARBITER_KEY" DATABASE_URL="$DATABASE_URL" \
    START_BLOCK=0 PORT="$1" POLL_MS=0 \
    "$NODE" --import tsx "$INDEXER/src/index.ts" >"$2" 2>&1 &
  echo $!
}

wait_health() {  # $1=port  $2=pid
  for _ in $(seq 1 120); do
    kill -0 "$2" 2>/dev/null || return 1  # process died
    if curl -s "http://127.0.0.1:$1/health" 2>/dev/null | grep -q '"ok"'; then return 0; fi
    sleep 0.5
  done
  return 1
}

# --- indexer #1: fresh ingest into postgres ----------------------------------
echo "== indexer #1: fresh ingest (backend=postgres, arbiter) =="
IX1_PID="$(start_indexer "$IX1_PORT" "$IX1_LOG")"
wait_health "$IX1_PORT" "$IX1_PID" || { cat "$IX1_LOG"; fail "indexer #1 did not become healthy"; }
grep -q "fresh ingest from block 0" "$IX1_LOG" || { cat "$IX1_LOG"; fail "indexer #1 was expected to fresh-ingest (no cursor)"; }

echo "== assert indexer #1 serves the scenario =="
"$NODE" --import tsx "$INDEXER/test/pg_assert.ts" "http://127.0.0.1:$IX1_PORT" "$FIXTURES" | tee "$IX1_LOG.assert"
grep -q "PG ASSERT PASS" "$IX1_LOG.assert" || fail "indexer #1 assertions failed"
SUM1="$(grep '^SUMMARY' "$IX1_LOG.assert")"
echo "   run1 $SUM1"

# --- kill #1, restart #2 against the SAME postgres ---------------------------
echo "== kill indexer #1, restart indexer #2 (same postgres) =="
kill "$IX1_PID" 2>/dev/null
wait "$IX1_PID" 2>/dev/null
IX1_PID=""

IX2_PID="$(start_indexer "$IX2_PORT" "$IX2_LOG")"
wait_health "$IX2_PORT" "$IX2_PID" || { cat "$IX2_LOG"; fail "indexer #2 did not become healthy"; }

# resume proof: #2 must have resumed from a >0 cursor, NOT replayed from block 0.
RESUME_LINE="$(grep 'resume from block' "$IX2_LOG" || true)"
[ -n "$RESUME_LINE" ] || { cat "$IX2_LOG"; fail "indexer #2 did NOT log a cursor resume"; }
RESUME_N="$(echo "$RESUME_LINE" | sed -n 's/.*resume from block \([0-9][0-9]*\).*/\1/p')"
[ -n "$RESUME_N" ] && [ "$RESUME_N" -gt 0 ] || { echo "$RESUME_LINE"; fail "resume block was not > 0"; }
grep -q "fresh ingest from block 0" "$IX2_LOG" && { cat "$IX2_LOG"; fail "indexer #2 replayed from block 0 (cursor resume failed)"; }
echo "   resume: $RESUME_LINE"

echo "== assert indexer #2 (post-restart) serves identical state =="
"$NODE" --import tsx "$INDEXER/test/pg_assert.ts" "http://127.0.0.1:$IX2_PORT" "$FIXTURES" | tee "$IX2_LOG.assert"
grep -q "PG ASSERT PASS" "$IX2_LOG.assert" || fail "indexer #2 assertions failed"
SUM2="$(grep '^SUMMARY' "$IX2_LOG.assert")"
echo "   run2 $SUM2"

# --- stability: the resumed instance is byte-identical to the fresh one -------
[ "$SUM1" = "$SUM2" ] || fail "resumed state differs from fresh state:
  run1: $SUM1
  run2: $SUM2"

rm -f "$IX1_LOG.assert" "$IX2_LOG.assert"

# --- crash-in-persist-window: atomic-persist resume convergence (BLOCKER proof) --
# A fresh `crashtest` database (dropped + recreated so the leg is re-runnable) so
# the fault-injection run never touches the DB the resume assertions above used.
echo ""
echo "== crash-in-persist-window leg: atomic persist closes the resume wedge =="
"$DOCKER" exec "$PG_NAME" psql -U postgres -q -c "DROP DATABASE IF EXISTS crashtest" >/dev/null 2>&1
"$DOCKER" exec "$PG_NAME" psql -U postgres -q -c "CREATE DATABASE crashtest" >/dev/null 2>&1 \
  || fail "could not create the crashtest database"
# The clean-reference run gets its OWN scratch db (the indexer is Postgres-only;
# the reference must never share state with the fault-injected crashtest db).
"$DOCKER" exec "$PG_NAME" psql -U postgres -q -c "DROP DATABASE IF EXISTS crashref" >/dev/null 2>&1
"$DOCKER" exec "$PG_NAME" psql -U postgres -q -c "CREATE DATABASE crashref" >/dev/null 2>&1 \
  || fail "could not create the crashref database"
RESUME_LOG="$(mktemp)"
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/crashtest" \
  REF_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/crashref" RPC="$E2E_RPC" \
  "$NODE" --import tsx "$INDEXER/test/pg_resume.ts" "$FIXTURES" | tee "$RESUME_LOG"
grep -q "PG RESUME GATE: PASS" "$RESUME_LOG" || { rm -f "$RESUME_LOG"; fail "crash-in-persist-window resume leg failed"; }
rm -f "$RESUME_LOG"

echo ""
echo "PG INTEGRATION GATE: PASS (adapters serve the scenario; restart resumed from block $RESUME_N with identical state; crash-in-persist-window leg proved atomic resume convergence)"
exit 0
