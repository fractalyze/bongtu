#!/usr/bin/env bash
# bongtu indexer conformance gate (SPEC §6b DoD-4).
#
# Starts a local anvil, deploys a fresh B=16 pool + runs the full scenario
# (deposit -> disburse(16) -> transfer -> withdraw -> receiver-tampered
# disburse -> authority-tampered disburse), ingests it with the indexer, and
# asserts: mirror.root == contract.root at head; /path folds; /events
# trial-decrypts to real leaves; /alarms carries "mismatch" for the
# receiver-tampered disburse and (arbiter mode) the envelope cross-check
# alarm for the authority-tampered one, whose batch stays unopened.
# Also runs the ARBITER-mode path (§6b v2): a second indexer holding the arbiter
# private key decrypts the authority envelopes into a note ledger (spent status
# from envelopes alone), serves /notes + within-batch /path, and /nullifiers.
#
#   cd indexer && npm test        # (== bash test/run.sh) exits 0 iff all pass
#
# anvil runs in the background and is trap-killed on exit (no GPU/ETH; CPU proofs
# against circuits/out zkeys, same as deploy/e2e_m0.sh).
#
# Postgres-only (U-I4): the gate ingests into REAL Postgres. TEST_DATABASE_URL
# (admin connection string) is honored when exported (CI service container);
# otherwise a throwaway postgres:16-alpine docker container is spun up and
# trap-removed. No postgres possible => LOUD skip (exit 0 with a banner).
set -uo pipefail

cd "$(dirname "$0")/.."
INDEXER="$(pwd)"
ROOT="$(cd ../.. && pwd)"

NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
DOCKER="${DOCKER:-$(command -v docker || echo docker)}"
PORT="${INDEXER_E2E_PORT:-8552}"
export E2E_RPC="http://127.0.0.1:${PORT}"

fail() { echo "FATAL: $*" >&2; exit 1; }

# Installed as the EXIT trap the moment the first background resource exists
# (the throwaway postgres), so a preflight fail cannot leak a container; every
# later resource (anvil) is guarded, unset-safe.
PG_NAME=""
cleanup() {
  [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null
  [ -n "${ANVIL_PID:-}" ] && wait "$ANVIL_PID" 2>/dev/null
  [ -n "${ANVIL_LOG:-}" ] && rm -f "$ANVIL_LOG"
  [ -n "$PG_NAME" ] && "$DOCKER" rm -f "$PG_NAME" >/dev/null 2>&1
}

# --- postgres (the indexer is Postgres-only, U-I4) ---------------------------
# The conformance test needs an ADMIN connection URL in TEST_DATABASE_URL (it
# creates its own per-instance databases). Use the caller's URL when exported
# (CI: the postgres service container); otherwise spin a throwaway
# postgres:16-alpine in docker on a random port (trap-removed below). Only when
# NEITHER is possible do we SKIP — loudly, never silently.
if [ -z "${TEST_DATABASE_URL:-}" ]; then
  if command -v "$DOCKER" >/dev/null 2>&1 && "$DOCKER" info >/dev/null 2>&1; then
    PG_PORT="${INDEXER_CONF_PG_PORT:-$((21000 + (RANDOM % 20000)))}"
    PG_NAME="bongtu-conf-pg-$$"
    trap cleanup EXIT INT TERM
    echo "== start throwaway postgres:16-alpine on :$PG_PORT (container $PG_NAME) =="
    "$DOCKER" run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=postgres \
      -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || fail "docker run postgres failed"
    PGREADY=0
    for _ in $(seq 1 60); do
      if "$DOCKER" exec "$PG_NAME" pg_isready -U postgres -q >/dev/null 2>&1; then PGREADY=1; break; fi
      sleep 0.5
    done
    [ "$PGREADY" = 1 ] || { "$DOCKER" logs "$PG_NAME" 2>&1 | tail -20; "$DOCKER" rm -f "$PG_NAME" >/dev/null 2>&1; fail "postgres did not become ready"; }
    export TEST_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/postgres"
  else
    echo "############################################################################" >&2
    echo "## SKIP: indexer conformance gate NOT RUN.                                ##" >&2
    echo "## The indexer is Postgres-only and this gate needs a real Postgres, but  ##" >&2
    echo "## TEST_DATABASE_URL is unset and docker is unavailable to spin one up.   ##" >&2
    echo "## Export TEST_DATABASE_URL (admin connection string) or install docker.  ##" >&2
    echo "############################################################################" >&2
    exit 0
  fi
fi

# --- preflight: contract build + proving artifacts present -------------------
echo "== preflight: forge build + zkey/wasm presence =="
( cd "$ROOT/contracts" && "$FORGE" build >/dev/null ) || fail "forge build failed"
for n in deposit disburse transfer transfer10 withdraw; do
  [ -f "$ROOT/circuits/out/${n}.zkey" ] || fail "missing circuits/out/${n}.zkey (run: cd circuits && bash prove_all.sh)"
  [ -f "$ROOT/circuits/out/${n}_js/${n}.wasm" ] || fail "missing circuits/out/${n}_js/${n}.wasm"
done

# --- start anvil -------------------------------------------------------------
ANVIL_LOG="$(mktemp)"
"$ANVIL" --port "$PORT" --silent >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!
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
