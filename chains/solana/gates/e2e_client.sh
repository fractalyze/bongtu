#!/usr/bin/env bash
# The Solana consumer-client acceptance gate (SOLR §5.3's client row, the
# heavy-gate sibling of deploy/gates/e2e_m0.sh): solana-test-validator + the
# deployed program + genesis-seeded pool accounts, the indexer Solana backend
# over live RPC, and the four consumer ops driven through the REAL client path
# by gates/client_leg.ts (derive keys -> deposit -> transfer -> self-scan
# balance -> withdraw, real CPU proofs). Heavy-gate discipline: run ONCE as
# the final gate; the mollusk suite (gates/mollusk.sh) stays the iteration
# loop.
#
#   bash chains/solana/gates/e2e_client.sh    # exits 0 iff every assertion holds
#
# Postgres-only indexer (U-I4): honors an exported SOLANA_E2E_DATABASE_URL,
# otherwise spins a throwaway postgres:16-alpine in docker (trap-removed).
# No Postgres possible is FATAL — the feed leg is the acceptance, never skip.
set -uo pipefail
cd "$(dirname "$0")/../../.."   # chains/solana/gates -> repo root

# Transaction v1 (SIMD-0385, the 4,096 B format every op here needs) requires
# an Agave 4.2+ validator; the repo's PINNED toolchain (active_release,
# AGAVE_VERSION in .github/ci-pins.env) stays on the mollusk build and is NOT
# flipped - this gate runs a side-by-side release instead:
#   mkdir -p "$HOME/.local/share/solana/install/releases/v4.2.2"
#   curl -fL https://release.anza.xyz/v4.2.2/solana-release-x86_64-unknown-linux-gnu.tar.bz2 \
#     | tar -xj -C "$HOME/.local/share/solana/install/releases/v4.2.2"
V1_BIN="${SOLANA_V1_BIN:-$HOME/.local/share/solana/install/releases/v4.2.2/solana-release/bin}"
[ -x "$V1_BIN/solana-test-validator" ] || {
  echo "FATAL: no Agave 4.2+ validator at $V1_BIN (set SOLANA_V1_BIN or install per the comment above); Transaction v1 needs it" >&2
  exit 1
}
export PATH="$V1_BIN:$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$PATH"
NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
DOCKER="${DOCKER:-$(command -v docker || echo docker)}"

fail() { echo "FATAL: $*" >&2; exit 1; }

# --- preflight ----------------------------------------------------------------
command -v solana-test-validator >/dev/null 2>&1 || fail "solana-test-validator not on PATH (Agave install)"
for n in depositPriv transferPriv transfer10x2Priv withdrawPriv; do
  [ -f "circuits/out/${n}.zkey" ] || fail "missing circuits/out/${n}.zkey (run: cd circuits && bash build/prove_all.sh)"
  [ -f "circuits/out/${n}_js/${n}.wasm" ] || fail "missing circuits/out/${n}_js/${n}.wasm"
done
if [ ! -f chains/solana/target/deploy/bongtu_pool_solana.so ]; then
  echo "== building the program (cargo-build-sbf) =="
  cargo-build-sbf --manifest-path chains/solana/program/Cargo.toml || fail "cargo-build-sbf failed"
fi

# --- postgres for the indexer -------------------------------------------------
PG_NAME=""
cleanup() {
  [ -n "$PG_NAME" ] && "$DOCKER" rm -f "$PG_NAME" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM
if [ -z "${SOLANA_E2E_DATABASE_URL:-}" ]; then
  if command -v "$DOCKER" >/dev/null 2>&1 && "$DOCKER" info >/dev/null 2>&1; then
    PG_PORT="${SOLANA_E2E_PG_PORT:-$((22000 + (RANDOM % 20000)))}"
    PG_NAME="bongtu-solana-client-pg-$$"
    echo "== start throwaway postgres:16-alpine on :$PG_PORT (container $PG_NAME) =="
    "$DOCKER" run -d --name "$PG_NAME" -e POSTGRES_PASSWORD=postgres \
      -p "127.0.0.1:${PG_PORT}:5432" postgres:16-alpine >/dev/null || fail "docker run postgres failed"
    PGREADY=0
    for _ in $(seq 1 60); do
      if "$DOCKER" exec "$PG_NAME" pg_isready -U postgres -q >/dev/null 2>&1; then PGREADY=1; break; fi
      sleep 0.5
    done
    [ "$PGREADY" = 1 ] || { "$DOCKER" logs "$PG_NAME" 2>&1 | tail -20; fail "postgres did not become ready"; }
    SOLANA_E2E_DATABASE_URL="postgres://postgres:postgres@127.0.0.1:${PG_PORT}/postgres"
  else
    fail "the indexer feed needs Postgres: export SOLANA_E2E_DATABASE_URL or make docker available (no silent skip)"
  fi
fi

# --- drive the leg ------------------------------------------------------------
echo "== running the consumer client leg =="
DATABASE_URL="$SOLANA_E2E_DATABASE_URL" "$NODE" --import tsx chains/solana/gates/client_leg.ts
RC=$?

echo ""
if [ "$RC" -eq 0 ]; then
  echo "SOLANA CLIENT GATE: PASS"
else
  echo "SOLANA CLIENT GATE: FAIL (rc=$RC)"
fi
exit "$RC"
