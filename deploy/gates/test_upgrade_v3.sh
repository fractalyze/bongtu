#!/usr/bin/env bash
# bongtu — the op-module (v3) UPGRADE drill (OPMOD §7).
#
# Proves the LIVE-pool migration path for the consumer module layer: an
# EXISTING enterprise proxy walked through the live pool's actual history
# (v1 deploy, then the shipped stealth-withdraw UpgradeV2 — the LIVE proxy
# sits at version 2) so the final `UpgradeV3.s.sol` leg is byte-for-byte the
# live one-shot, landing with the module registry live and the enterprise
# storage + behavior intact.
#   - boots a scratch anvil, runs Deploy.s.sol (full B=256 enterprise stack,
#     version slot 1)
#   - runs UpgradeV2.s.sol (stealth-withdraw verifier + impl +
#     reinitializeV2) to reproduce the live proxy's version-2 state
#   - runs UpgradeV3.s.sol (MODULE_PROFILE=consumer default) with the SAME
#     deployer: consumer verifiers + 5 modules + ONE upgradeToAndCall
#     carrying reinitializeV3(modules)
#   - asserts: Initializable slot walks 1 -> 2 -> 3, every module in the
#     written deploy/modules.31337.json reads registeredModules == true
#     on-chain, poolImpl rotated, B()==256 survives, withdrawVerifier NOT
#     rotated by the v3 leg (v2 rotated it; v3 must not touch it)
#   - runs Smoke.s.sol post-upgrade: the committed REAL enterprise deposit
#     fixture proof must still be accepted (nextLeafIndex 0 -> 2) — the
#     enterprise entrypoints are byte-untouched through the module upgrade
#   - rerun refusal: reinitializer(3) is consumed — asserted on the guard's
#     own message from a captured log, plus an anvil liveness check, so an
#     infrastructure crash cannot masquerade as the refusal
#
#   cd bongtu && bash deploy/gates/test_upgrade_v3.sh   # exits 0 iff all pass
#
# NOTE: rewrites deploy/addresses.31337.json + deploy/modules.31337.json
# (scratch records). Kills the anvil on exit. No errexit — explicit asserts
# via `fail`, same as the sibling gates.
set -uo pipefail

cd "$(dirname "$0")/../.."   # deploy/gates -> repo root

FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${UPGRADE_DRILL_PORT:-8563}"
RPC="http://127.0.0.1:${PORT}"
ADDR="deploy/addresses.31337.json"
MODS="deploy/modules.31337.json"
INIT_SLOT=0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00

fail() { echo "FATAL: $*" >&2; exit 1; }
jf() { python3 -c "import json,sys; print(json.load(open('$ADDR'))['$1'])"; }
jm() { python3 -c "import json,sys; print(json.load(open('$MODS'))['$1'])"; }

"$ANVIL" --port "$PORT" --silent &
ANVIL_PID=$!
cleanup() { kill "$ANVIL_PID" 2>/dev/null; }
trap cleanup EXIT
for _ in $(seq 1 50); do "$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

echo "== deploy (v1-initialized enterprise proxy, B=256) =="
(cd contracts && "$FORGE" script ../deploy/forge/Deploy.s.sol:Deploy \
  --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 || fail "Deploy.s.sol failed"

POOL=$(jf pool)
SLOT1=$("$CAST" storage "$POOL" "$INIT_SLOT" --rpc-url "$RPC")
[ "$(printf '%d' "$SLOT1" 2>/dev/null || echo 0)" -eq 1 ] || fail "fresh proxy is not at initializer version 1"

echo "== upgrade to v2 (UpgradeV2.s.sol, stealth withdraw — the live proxy's shipped state) =="
(cd contracts && "$FORGE" script ../deploy/forge/UpgradeV2.s.sol:UpgradeV2 \
  --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 || fail "UpgradeV2.s.sol failed"
SLOT2=$("$CAST" storage "$POOL" "$INIT_SLOT" --rpc-url "$RPC")
[ "$(printf '%d' "$SLOT2" 2>/dev/null || echo 0)" -eq 2 ] || fail "initializer version is not 2 after UpgradeV2 (got $SLOT2)"

# v2 rotated poolImpl + withdrawVerifier; snapshot AFTER it so the v3 asserts
# measure only what the v3 leg itself did.
PRE_IMPL=$(jf poolImpl); PRE_WV=$(jf withdrawVerifier)

echo "== upgrade (UpgradeV3.s.sol, MODULE_PROFILE=consumer) =="
(cd contracts && "$FORGE" script ../deploy/forge/UpgradeV3.s.sol:UpgradeV3 \
  --rpc-url "$RPC" --broadcast --skip-simulation) || fail "UpgradeV3.s.sol failed"

[ -f "$MODS" ] || fail "missing $MODS (upgrade did not record the module set)"
POST_IMPL=$(jf poolImpl)
[ "$POST_IMPL" != "$PRE_IMPL" ] || fail "poolImpl did not rotate in the record"
[ "$(jf withdrawVerifier)" = "$PRE_WV" ] || fail "withdrawVerifier must not rotate in a v3 upgrade"

SLOT3=$("$CAST" storage "$POOL" "$INIT_SLOT" --rpc-url "$RPC")
[ "$(printf '%d' "$SLOT3" 2>/dev/null || echo 0)" -eq 3 ] || fail "initializer version is not 3 (got $SLOT3)"
B=$("$CAST" call "$POOL" "B()(uint256)" --rpc-url "$RPC")
[ "$B" = "256" ] || fail "B() != 256 after upgrade (got $B)"
[ "$(jm pool)" = "$POOL" ] || fail "modules record names a different pool"

for M in depositPrivModule transferPrivModule transfer10x2PrivModule withdrawPrivModule consumerDisburseModule; do
  MOD=$(jm "$M")
  REG=$("$CAST" call "$POOL" "registeredModules(address)(bool)" "$MOD" --rpc-url "$RPC")
  [ "$REG" = "true" ] || fail "$M ($MOD) not registered on-chain"
  echo "   registered: $M = $MOD"
done

echo "== enterprise smoke post-upgrade (real deposit fixture proof) =="
(cd contracts && "$FORGE" script ../deploy/forge/Smoke.s.sol:Smoke \
  --rpc-url "$RPC" --broadcast --skip-simulation) || fail "post-upgrade enterprise Smoke failed"
NLI=$("$CAST" call "$POOL" "nextLeafIndex()(uint256)" --rpc-url "$RPC")
[ "$NLI" = "2" ] || fail "post-upgrade smoke deposit did not advance nextLeafIndex to 2 (got $NLI)"

echo "== rerun refusal (reinitializer consumed) =="
RERUN_LOG="$(mktemp)"
(cd contracts && "$FORGE" script ../deploy/forge/UpgradeV3.s.sol:UpgradeV3 \
  --rpc-url "$RPC" --broadcast --skip-simulation) >"$RERUN_LOG" 2>&1 \
  && { cat "$RERUN_LOG"; fail "second UpgradeV3 run must refuse (version guard)"; }
# The refusal must be the _guards version check, not an anvil crash or any
# other failure — assert on the guard's own message from UpgradeV3.s.sol.
grep -q "pool already reinitialized past v2" "$RERUN_LOG" \
  || { cat "$RERUN_LOG"; fail "second run failed for a reason other than the version guard"; }
rm -f "$RERUN_LOG"
# ...and the chain must still be alive: infrastructure death cannot masquerade
# as the intended refusal.
"$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1 || fail "anvil is not answering after the rerun-refusal leg"
echo "   PASS: second run refused (version guard, anvil alive)"

echo "UPGRADE V3 DRILL: PASS"
