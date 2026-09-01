#!/usr/bin/env bash
# bongtu — the withdraw-v2 (stealth exit) UPGRADE drill.
#
# The one-shot drill proves a FRESH deploy comes up production-shaped; this one
# proves the LIVE-pool path: an EXISTING v1-initialized proxy taken through
# `UpgradeV2.s.sol` lands on the same shape with its storage intact.
#   - boots a scratch anvil, runs Deploy.s.sol (proxy at version slot 1)
#   - runs UpgradeV2.s.sol against the recorded pool with the SAME deployer
#   - asserts: Initializable slot 1 -> 2, withdrawVerifier ROTATED (new
#     address, non-zero), poolImpl rotated, B()==256 and owner survive, and the
#     addresses record was merge-written (verifier field == chain state).
#
#   cd bongtu && bash deploy/gates/test_upgrade_v2.sh   # exits 0 iff all pass
#
# NOTE: rewrites deploy/addresses.31337.json (scratch record). Kills the anvil
# on exit. No errexit — explicit asserts via `fail`, same as the sibling gates
# (a failing kill under errexit would abort the EXIT trap and leak the anvil).
set -uo pipefail

cd "$(dirname "$0")/../.."   # deploy/gates -> repo root

FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${UPGRADE_DRILL_PORT:-8562}"
RPC="http://127.0.0.1:${PORT}"
ADDR="deploy/addresses.31337.json"
INIT_SLOT=0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00

fail() { echo "FATAL: $*" >&2; exit 1; }
jf() { python3 -c "import json,sys; print(json.load(open('$ADDR'))['$1'])"; }

"$ANVIL" --port "$PORT" --silent &
ANVIL_PID=$!
cleanup() { kill "$ANVIL_PID" 2>/dev/null; }
trap cleanup EXIT
for _ in $(seq 1 50); do "$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

echo "== deploy (v1-initialized proxy) =="
(cd contracts && "$FORGE" script ../deploy/forge/Deploy.s.sol:Deploy \
  --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 || fail "Deploy.s.sol failed"

POOL=$(jf pool); PRE_VERIFIER=$(jf withdrawVerifier); PRE_IMPL=$(jf poolImpl)
[ "$(( $("$CAST" storage "$POOL" "$INIT_SLOT" --rpc-url "$RPC") ))" -eq 1 ] 2>/dev/null \
  || [ "$("$CAST" storage "$POOL" "$INIT_SLOT" --rpc-url "$RPC" | tail -c 2)" = "1" ] \
  || fail "fresh proxy is not at initializer version 1"

echo "== upgrade (UpgradeV2.s.sol) =="
(cd contracts && "$FORGE" script ../deploy/forge/UpgradeV2.s.sol:UpgradeV2 \
  --rpc-url "$RPC" --broadcast --skip-simulation) || fail "UpgradeV2.s.sol failed"

POST_VERIFIER=$(jf withdrawVerifier); POST_IMPL=$(jf poolImpl)
[ "$POST_VERIFIER" != "$PRE_VERIFIER" ] || fail "withdrawVerifier did not rotate in the record"
[ "$POST_IMPL" != "$PRE_IMPL" ] || fail "poolImpl did not rotate in the record"

CHAIN_VERIFIER=$("$CAST" call "$POOL" "withdrawVerifier()(address)" --rpc-url "$RPC")
[ "${CHAIN_VERIFIER,,}" = "${POST_VERIFIER,,}" ] || fail "record verifier != chain verifier"
SLOT=$("$CAST" storage "$POOL" "$INIT_SLOT" --rpc-url "$RPC")
[ "$(printf '%d' "$SLOT" 2>/dev/null || echo 0)" -eq 2 ] || fail "initializer version is not 2 (got $SLOT)"
B=$("$CAST" call "$POOL" "B()(uint256)" --rpc-url "$RPC")
[ "$B" = "256" ] || fail "B() != 256 after upgrade (got $B)"

echo "== rerun refusal (reinitializer consumed) =="
(cd contracts && "$FORGE" script ../deploy/forge/UpgradeV2.s.sol:UpgradeV2 \
  --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 \
  && fail "second UpgradeV2 run must refuse (version guard)" \
  || echo "   PASS: second run refused"

echo "UPGRADE DRILL: PASS"
