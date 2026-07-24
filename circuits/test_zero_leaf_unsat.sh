#!/usr/bin/env bash
# §5.2 CRITICAL-correction security regression (SPEC §5.2, docs/zeto-derivation.md).
#
# Proves the zero-commitment belt `enabled[i] * IsZero(inputCommitments[i]) === 0`
# closes the SMT->IMT zero-leaf mint-from-nothing at the CIRCUIT level, for ALL
# THREE spending circuits (transfer + withdraw permissionless, disburse caller-gated),
# while leaving honest spends provable.
#
# For each of transfer, withdraw:
#   <name>_zero_leaf  (commitment=0, value=X, enabled=1, fresh nullifier, genuine
#                      zeros-membership) -> generate_witness MUST THROW on the belt
#                      (Assert Failed, in the spending base template);
#   <name>            (the honest gen_inputs.ts fixture)
#                     -> generate_witness MUST SUCCEED (belt does not reject legit spends).
#
# Exits 0 iff BOTH exploit witness-gens fail on the belt AND BOTH honest witness-gens
# succeed; nonzero otherwise. Compiles transfer/withdraw if their wasm is missing, so
# the gate is self-contained.
#
#   cd circuits && bash test_zero_leaf_unsat.sh
set -uo pipefail

cd "$(dirname "$0")"

CIRCOM='/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom'
NODE=/home/a41/.nvm/versions/node/v22.17.1/bin/node
ZETO=/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits

mkdir -p out inputs
# circom's generated generate_witness.js is CommonJS; the repo root is ESM, so mark
# the (gitignored) out/ tree as CommonJS to load the helper unchanged.
echo '{ "type": "commonjs" }' > out/package.json

echo "== regenerating honest + zero-leaf exploit input fixtures =="
$NODE --import tsx gen_inputs.ts            || { echo "FATAL: honest input gen failed"; exit 1; }
$NODE --import tsx gen_zero_leaf_inputs.ts  || { echo "FATAL: transfer/withdraw zero-leaf input gen failed"; exit 1; }
$NODE --import tsx gen_disburse_zero_leaf.ts || { echo "FATAL: disburse zero-leaf input gen failed"; exit 1; }

compile_if_missing() {
  local name="$1"
  if [ ! -f "out/${name}_js/${name}.wasm" ]; then
    echo "-- compiling $name (wasm missing)"
    $CIRCOM "$name.circom" --r1cs --wasm --sym -o out/ \
        -l "$ZETO" -l "$ZETO/node_modules" -l lib \
        || { echo "FATAL: $name compile failed"; exit 1; }
  fi
}

# Run generate_witness; echo "OK" on success, "THROW" plus captured output on failure.
run_witness() {
  local name="$1" fixture="$2"
  local wasm="out/${name}_js/${name}.wasm"
  local gen="out/${name}_js/generate_witness.js"
  if $NODE "$gen" "$wasm" "inputs/${fixture}.json" "out/${fixture}.wtns" >/tmp/zl_${fixture}.log 2>&1; then
    echo "OK"
  else
    echo "THROW"
  fi
}

declare -A TEMPLATE=( [transfer]="ZetoTransferSmall" [withdraw]="CheckNullifiersInputsOutputsValueIMT" [disburse]="Zeto" )
failures=0

for name in transfer withdraw disburse; do
  compile_if_missing "$name"
  tmpl="${TEMPLATE[$name]}"

  echo ""
  echo "== $name: EXPLOIT (${name}_zero_leaf) must be UNSATISFIABLE on the belt =="
  res=$(run_witness "$name" "${name}_zero_leaf")
  log="/tmp/zl_${name}_zero_leaf.log"
  if [ "$res" = "OK" ]; then
    echo "FAIL: ${name}_zero_leaf produced a witness — the zero-leaf belt did NOT reject it"
    failures=$((failures+1))
  elif grep -q "Assert Failed" "$log" && grep -q "$tmpl" "$log"; then
    echo "PASS: ${name}_zero_leaf witness-gen THROWS on the belt (Assert Failed in $tmpl)"
    grep -E "Assert Failed|$tmpl|line:" "$log" | head -3 | sed 's/^/    /'
  else
    echo "FAIL: ${name}_zero_leaf threw, but not on the belt assertion in $tmpl. Output:"
    sed 's/^/    /' "$log" | head -15
    failures=$((failures+1))
  fi

  echo "== $name: HONEST ($name) must still SUCCEED =="
  res=$(run_witness "$name" "$name")
  log="/tmp/zl_${name}.log"
  if [ "$res" = "OK" ]; then
    echo "PASS: honest $name witness-gen SUCCEEDS (belt does not reject legitimate spends)"
  else
    echo "FAIL: honest $name witness-gen THREW — the belt is rejecting a legitimate spend. Output:"
    sed 's/^/    /' "$log" | head -15
    failures=$((failures+1))
  fi
done

echo ""
echo "======================================================================"
if [ "$failures" -eq 0 ]; then
  echo "ZERO-LEAF BELT GATE: PASS — the zero-commitment mint-from-nothing is"
  echo "unsatisfiable at witness-gen for transfer, withdraw AND disburse; honest spends prove."
  exit 0
else
  echo "ZERO-LEAF BELT GATE: FAIL ($failures)"
  exit 1
fi
