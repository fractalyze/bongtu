#!/usr/bin/env bash
# bongtu — the receive-factory add-on deploy drill: a fresh Deploy.s.sol record
# (consumer module profile) taken through DeployReceive.s.sol lands the factory,
# records it, and refuses a rerun (a second factory would strand issued
# announcements). Also proves the module-set precondition: without a recorded
# depositPrivModule the deploy must refuse. Scratch anvil, rewrites
# deploy/addresses.31337.json + modules.31337.json; honest rc via explicit asserts.
set -uo pipefail
cd "$(dirname "$0")/../.."
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${RECEIVE_DRILL_PORT:-8564}"
RPC="http://127.0.0.1:${PORT}"
ADDR="deploy/addresses.31337.json"
MODS="deploy/modules.31337.json"
fail() { echo "FATAL: $*" >&2; exit 1; }
jf() { python3 -c "import json;print(json.load(open('$ADDR')).get('$1',''))"; }

"$ANVIL" --port "$PORT" --silent & ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do "$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

(cd chains/evm && MODULE_PROFILE=consumer "$FORGE" script ../../deploy/forge/Deploy.s.sol:Deploy --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 || fail "Deploy failed"
[ -z "$(jf receiveFactory)" ] || fail "fresh record must not carry a receive factory"

echo "== module-set precondition =="
mv "$MODS" "$MODS.aside"
(cd chains/evm && "$FORGE" script ../../deploy/forge/DeployReceive.s.sol:DeployReceive --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 && \
  { mv "$MODS.aside" "$MODS"; fail "deploy without a module record must refuse"; } || echo "   PASS: refused without depositPrivModule"
mv "$MODS.aside" "$MODS"

echo "== deploy with the consumer module set =="
(cd chains/evm && "$FORGE" script ../../deploy/forge/DeployReceive.s.sol:DeployReceive --rpc-url "$RPC" --broadcast --skip-simulation) || fail "DeployReceive failed"
F=$(jf receiveFactory); [ -n "$F" ] || fail "receiveFactory not recorded"
OWNER=$("$CAST" call "$F" "owner()(address)" --rpc-url "$RPC")
DEPLOYER=$("$CAST" wallet address --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
[ "${OWNER,,}" = "${DEPLOYER,,}" ] || fail "owner != bot default"
SALT="0x0000000000000000000000002222222222222222222222222222222222222222"
"$CAST" call "$F" "addressOf(bytes32)(address)" "$SALT" --rpc-url "$RPC" >/dev/null || fail "addressOf unreachable"

echo "== rerun refusal =="
(cd chains/evm && "$FORGE" script ../../deploy/forge/DeployReceive.s.sol:DeployReceive --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 && fail "rerun must refuse" || echo "   PASS: rerun refused"
echo "RECEIVE DEPLOY DRILL: PASS"
