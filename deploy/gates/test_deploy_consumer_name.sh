#!/usr/bin/env bash
# bongtu — the consumer-profile name deploy drill: DeployConsumerOnly ->
# DeployPortalPriv (RECORD_PROFILE=consumer) -> DeployNameResolver lands the
# whole Sepolia-demo contract set against the CONSUMER record pair, records
# every add-on field, and refuses reruns and missing preconditions. Scratch
# anvil, rewrites deploy/addresses.consumer.31337.json +
# modules.consumer.31337.json; honest rc via explicit asserts.
set -uo pipefail
cd "$(dirname "$0")/../.."
FORGE="${FORGE:-$(command -v forge || echo /home/a41/.foundry/bin/forge)}"
ANVIL="${ANVIL:-$(command -v anvil || echo /home/a41/.foundry/bin/anvil)}"
CAST="${CAST:-$(command -v cast || echo /home/a41/.foundry/bin/cast)}"
PORT="${CONSUMER_NAME_DRILL_PORT:-8565}"
RPC="http://127.0.0.1:${PORT}"
ADDR="deploy/addresses.consumer.31337.json"
MODS="deploy/modules.consumer.31337.json"
URL="https://gateway.invalid/ens/{sender}/{data}.json"
fail() { echo "FATAL: $*" >&2; exit 1; }
jf() { python3 -c "import json;print(json.load(open('$ADDR')).get('$1',''))"; }

"$ANVIL" --port "$PORT" --silent & ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do "$CAST" chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done

echo "== consumer-only stack =="
(cd chains/evm && "$FORGE" script ../../deploy/forge/DeployConsumerOnly.s.sol:DeployConsumerOnly --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 || fail "DeployConsumerOnly failed"
[ -n "$(jf pool)" ] || fail "pool not recorded"
[ -z "$(jf portalPrivFactory)" ] || fail "fresh consumer record must not carry a priv factory"
[ -z "$(jf resolver)" ] || fail "fresh consumer record must not carry a resolver"

echo "== resolver precondition: factory first =="
(cd chains/evm && GATEWAY_URL="$URL" "$FORGE" script ../../deploy/forge/DeployNameResolver.s.sol:DeployNameResolver --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 && \
  fail "resolver deploy without the priv factory must refuse" || echo "   PASS: refused without portalPrivFactory"

echo "== priv factory on the consumer record =="
(cd chains/evm && RECORD_PROFILE=consumer "$FORGE" script ../../deploy/forge/DeployPortalPriv.s.sol:DeployPortalPriv --rpc-url "$RPC" --broadcast --skip-simulation) || fail "DeployPortalPriv (consumer) failed"
F=$(jf portalPrivFactory); [ -n "$F" ] || fail "portalPrivFactory not recorded on the consumer record"
"$CAST" call "$F" "sweeperInitCodeHash()(bytes32)" --rpc-url "$RPC" >/dev/null || fail "factory unreachable"
(cd chains/evm && RECORD_PROFILE=consumer "$FORGE" script ../../deploy/forge/DeployPortalPriv.s.sol:DeployPortalPriv --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 && \
  fail "priv factory rerun must refuse" || echo "   PASS: factory rerun refused"

echo "== name resolver =="
(cd chains/evm && GATEWAY_URL="$URL" "$FORGE" script ../../deploy/forge/DeployNameResolver.s.sol:DeployNameResolver --rpc-url "$RPC" --broadcast --skip-simulation) || fail "DeployNameResolver failed"
R=$(jf resolver); [ -n "$R" ] || fail "resolver not recorded"
[ -n "$(jf gatewaySigner)" ] || fail "gatewaySigner not recorded"
[ "$(jf gatewayUrl)" = "$URL" ] || fail "gatewayUrl not recorded"
SIGNER=$("$CAST" call "$R" "signer()(address)" --rpc-url "$RPC")
DEPLOYER=$("$CAST" wallet address --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80)
[ "${SIGNER,,}" = "${DEPLOYER,,}" ] || fail "signer default != deployer"
SUPPORTS=$("$CAST" call "$R" "supportsInterface(bytes4)(bool)" 0x9061b923 --rpc-url "$RPC")
[ "$SUPPORTS" = "true" ] || fail "ENSIP-10 interface not reported"
# The factory survived the resolver's merge-write (ConsumerBook owns the field list).
[ "$(jf portalPrivFactory)" = "$F" ] || fail "resolver deploy dropped the recorded factory"

echo "== resolver rerun refusal =="
(cd chains/evm && GATEWAY_URL="$URL" "$FORGE" script ../../deploy/forge/DeployNameResolver.s.sol:DeployNameResolver --rpc-url "$RPC" --broadcast --skip-simulation) >/dev/null 2>&1 && \
  fail "resolver rerun must refuse" || echo "   PASS: resolver rerun refused"

echo "CONSUMER NAME DEPLOY DRILL: PASS"
