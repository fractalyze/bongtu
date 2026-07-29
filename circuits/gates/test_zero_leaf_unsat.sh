#!/usr/bin/env bash
# §5.2 CRITICAL-correction security regression (SPEC §5.2, docs/zeto-derivation.md).
#
# Proves the zero-commitment belt `enabled[i] * IsZero(inputCommitments[i]) === 0`
# closes the SMT->IMT zero-leaf mint-from-nothing at the CIRCUIT level, for ALL
# FIVE spending circuits (all permissionless — the disburse caller allowlist
# retired 2026-07-28), while leaving honest spends provable.
# The two 10-input circuits put their exploit in a middle slot (7 of 10), where a
# per-slot belt is easiest to get wrong.
#
# For each spending circuit:
#   <name>_zero_leaf  (commitment=0, value=X, enabled=1, fresh nullifier, genuine
#                      zeros-membership) -> generate_witness MUST THROW on the belt
#                      (Assert Failed, in the spending base template);
#   <name>            (the honest fixtures/gen_inputs.ts fixture)
#                     -> generate_witness MUST SUCCEED (belt does not reject legit spends).
#
# Exits 0 iff BOTH exploit witness-gens fail on the belt AND BOTH honest witness-gens
# succeed; nonzero otherwise. Compiles transfer/withdraw if their wasm is missing, so
# the gate is self-contained.
#
#   cd bongtu && bash circuits/gates/test_zero_leaf_unsat.sh
set -uo pipefail

cd "$(dirname "$0")/.."   # circuits/gates -> circuits

# Overridable toolchain (same pattern as build/prove_all.sh / deploy/gates/e2e_m0.sh): CI and
# fresh machines export CIRCOM, NODE, ZETO, CIRCOMLIB; the defaults are this dev
# box (docs/toolchain.md). CIRCOM may be a multi-word command (ld-linux shim).
CIRCOM="${CIRCOM:-/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom}"
NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
ZETO="${ZETO:-/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits}"
CIRCOMLIB="${CIRCOMLIB:-$ZETO/node_modules}"

mkdir -p out fixtures/inputs
# circom's generated generate_witness.js is CommonJS; the repo root is ESM, so mark
# the (gitignored) out/ tree as CommonJS to load the helper unchanged.
echo '{ "type": "commonjs" }' > out/package.json

echo "== regenerating honest + zero-leaf exploit input fixtures =="
$NODE --import tsx fixtures/gen_inputs.ts            || { echo "FATAL: honest input gen failed"; exit 1; }
$NODE --import tsx fixtures/gen_zero_leaf_inputs.ts  || { echo "FATAL: transfer/withdraw zero-leaf input gen failed"; exit 1; }
$NODE --import tsx fixtures/gen_disburse_zero_leaf.ts || { echo "FATAL: disburse zero-leaf input gen failed"; exit 1; }

compile_if_missing() {
  local name="$1"
  if [ ! -f "out/${name}_js/${name}.wasm" ]; then
    echo "-- compiling $name (wasm missing)"
    $CIRCOM "$name.circom" --r1cs --wasm --sym -o out/ \
        -l "$ZETO" -l "$CIRCOMLIB" -l lib \
        || { echo "FATAL: $name compile failed"; exit 1; }
  fi
}

# Run generate_witness; echo "OK" on success, "THROW" plus captured output on failure.
run_witness() {
  local name="$1" fixture="$2"
  local wasm="out/${name}_js/${name}.wasm"
  local gen="out/${name}_js/generate_witness.js"
  if $NODE "$gen" "$wasm" "fixtures/inputs/${fixture}.json" "out/${fixture}.wtns" >/tmp/zl_${fixture}.log 2>&1; then
    echo "OK"
  else
    echo "THROW"
  fi
}

# Template name the belt assertion must be reported from. transfer10 and
# transfer10x2 share transfer's template — they are the same base at other arities.
declare -A TEMPLATE=(
  [transfer]="ZetoTransferSmall"
  [transfer10]="ZetoTransferSmall"
  [transfer10x2]="ZetoTransferSmall"
  [withdraw]="CheckNullifiersInputsOutputsValueIMT"
  [disburse]="Zeto"
)
failures=0

for name in transfer transfer10 transfer10x2 withdraw disburse; do
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
  echo "unsatisfiable at witness-gen for transfer, transfer10, transfer10x2, withdraw AND disburse; honest spends prove."
  exit 0
else
  echo "ZERO-LEAF BELT GATE: FAIL ($failures)"
  exit 1
fi
