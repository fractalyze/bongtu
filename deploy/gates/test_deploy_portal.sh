#!/usr/bin/env bash
# bongtu — the portal-factory add-on deploy drill: a fresh Deploy.s.sol record
# taken through DeployPortal.s.sol lands the factory, records it, and refuses a
# rerun (a second factory would strand issued announcements). Scratch anvil,
# rewrites deploy/addresses.31337.json; honest rc via explicit asserts.
set -uo pipefail
cd "$(dirname "$0")/../.."
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${PORTAL_DRILL_PORT:-8563}"
RPC="http://127.0.0.1:${PORT}"
ADDR="deploy/addresses.31337.json"
fail() { echo "FATAL: $*" >&2; exit 1; }
jf() { python3 -c "import json;print(json.load(open('$ADDR')).get('$1',''))"; }

"$ANVIL" --port "$PORT" --silent & ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do "$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

(cd contracts && "$FORGE" script ../deploy/forge/Deploy.s.sol:Deploy --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 || fail "Deploy failed"
[ -z "$(jf portalFactory)" ] || fail "fresh record must not carry a factory"
(cd contracts && "$FORGE" script ../deploy/forge/DeployPortal.s.sol:DeployPortal --rpc-url "$RPC" --broadcast --skip-simulation) || fail "DeployPortal failed"
F=$(jf portalFactory); [ -n "$F" ] || fail "portalFactory not recorded"
OWNER=$("$CAST" call "$F" "owner()(address)" --rpc-url "$RPC")
DEPLOYER=$("$CAST" wallet address --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
[ "${OWNER,,}" = "${DEPLOYER,,}" ] || fail "owner != bot default"
"$CAST" call "$F" "addressOf(bytes32)(address)" 0x00000000000000000000000011"11111111111111111111111111111111111111" --rpc-url "$RPC" >/dev/null 2>&1 || \
  "$CAST" call "$F" "addressOf(bytes32)(address)" $(printf '0x%064x' 0x1111111111111111111111111111111111111111) --rpc-url "$RPC" >/dev/null || fail "addressOf unreachable"
echo "== rerun refusal =="
(cd contracts && "$FORGE" script ../deploy/forge/DeployPortal.s.sol:DeployPortal --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 && fail "rerun must refuse" || echo "   PASS: rerun refused"
echo "PORTAL DEPLOY DRILL: PASS"
