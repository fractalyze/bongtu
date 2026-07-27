#!/usr/bin/env bash
# bongtu M0 Unit U2 gate (spec §4, .dev/milestone-m0.md Done#2).
#
# For each circuit: compile -> groth16 setup (pot22) -> export vkey + solidity
# verifier -> generate_witness from the JS-produced input.json -> groth16 prove
# -> groth16 verify. Prints "[INFO] snarkJS: OK" once per fixture and exits 0
# when all of them verify. Verifier .sol files are copied into verifiers/
# (committed; they feed U3). Reports r1cs constraint + public-signal counts.
#
# A circuit may carry EXTRA fixtures beyond its same-named one (transfer10 has
# both the partly-filled spend and the 10-input consolidation); those reuse the
# circuit's zkey and count as their own gate legs.
#
#   cd circuits && bash prove_all.sh                # all circuits
#   cd circuits && bash prove_all.sh transfer10     # just one (targeted regen)
#
# Not idempotency-fragile: out/ is regenerated each run; .zkey/.wtns/.r1cs are
# gitignored. `groth16 setup` is deterministic for a given (r1cs, ptau), so a
# re-run reproduces the committed verifiers byte-for-byte — regenerating one
# circuit cannot invalidate another circuit's committed proof fixtures.
set -uo pipefail

cd "$(dirname "$0")"

# Overridable toolchain (same pattern as deploy/e2e_m0.sh): CI / fresh machines
# export CIRCOM, SNARKJS, NODE, ZETO, CIRCOMLIB, PTAU; defaults are this dev box
# (docs/toolchain.md). CIRCOM may be a multi-word command (ld-linux shim).
CIRCOM="${CIRCOM:-/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom}"
SNARKJS="${SNARKJS:-node --max-old-space-size=16000 /home/a41/Workspace/zkx-snap/circuits/node_modules/.bin/snarkjs}"
NODE="${NODE:-$(command -v node || echo /home/a41/.nvm/versions/node/v22.17.1/bin/node)}"
ZETO="${ZETO:-/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits}"
CIRCOMLIB="${CIRCOMLIB:-$ZETO/node_modules}"
PTAU="${PTAU:-/home/a41/Workspace/zkx-snap/circuits/ptau/pot22_hez.ptau}"

mkdir -p out verifiers inputs
# circom emits CommonJS witness helpers (out/<name>_js/generate_witness.js uses
# `require`). The repo root is now an ESM package ("type":"module"), which would
# otherwise make Node treat those generated .js as ESM and fail. Mark the whole
# (gitignored) out/ tree as CommonJS so the generated helpers load unchanged.
echo '{ "type": "commonjs" }' > out/package.json

echo "== regenerating input fixtures =="
$NODE --import tsx gen_inputs.ts || { echo "FATAL: input generation failed"; exit 1; }

ALL_CIRCUITS=(deposit disburse transfer transfer10 withdraw)
if [ "$#" -gt 0 ]; then CIRCUITS=("$@"); else CIRCUITS=("${ALL_CIRCUITS[@]}"); fi

# Fixtures proved against a circuit's zkey ON TOP of its same-named one.
extra_fixtures() {
  case "$1" in
    transfer10) echo "transfer10_consolidate" ;;
    *) echo "" ;;
  esac
}

declare -A PASS
LEGS=()
OK_COUNT=0

# witness -> prove -> verify one fixture against <circuit>.zkey. Records PASS
# under the FIXTURE name, so each fixture is its own line in the summary.
run_fixture() {
  local circuit="$1" fixture="$2"

  echo "-- generate witness ($fixture)"
  $NODE "out/${circuit}_js/generate_witness.js" "out/${circuit}_js/$circuit.wasm" "inputs/$fixture.json" "out/$fixture.wtns" \
      || { echo "$fixture: witness generation FAILED"; return; }

  echo "-- groth16 prove ($fixture)"
  $SNARKJS groth16 prove "out/$circuit.zkey" "out/$fixture.wtns" "out/$fixture.proof.json" "out/$fixture.public.json" \
      || { echo "$fixture: prove FAILED"; return; }

  echo "-- public signal count: $($NODE -e "console.log(require('./out/$fixture.public.json').length)")"

  echo "-- groth16 verify ($fixture)"
  if $SNARKJS groth16 verify "out/$circuit.vkey.json" "out/$fixture.public.json" "out/$fixture.proof.json"; then
    PASS[$fixture]=1
    OK_COUNT=$((OK_COUNT+1))
  else
    echo "$fixture: verify FAILED"
  fi
}

run_circuit() {
  local name="$1"
  echo ""
  echo "======================================================================"
  echo "== $name"
  echo "======================================================================"

  echo "-- compile"
  $CIRCOM "$name.circom" --r1cs --wasm --sym -o out/ \
      -l "$ZETO" -l "$CIRCOMLIB" -l lib || { echo "$name: compile FAILED"; return; }

  echo "-- r1cs info"
  $SNARKJS r1cs info "out/$name.r1cs" || { echo "$name: r1cs info FAILED"; return; }

  echo "-- groth16 setup"
  $SNARKJS groth16 setup "out/$name.r1cs" "$PTAU" "out/$name.zkey" || { echo "$name: setup FAILED"; return; }

  echo "-- export verification key"
  $SNARKJS zkey export verificationkey "out/$name.zkey" "out/$name.vkey.json" || { echo "$name: vkey export FAILED"; return; }

  echo "-- export solidity verifier"
  $SNARKJS zkey export solidityverifier "out/$name.zkey" "out/${name}_verifier.sol" || { echo "$name: sol export FAILED"; return; }
  cp "out/${name}_verifier.sol" "verifiers/${name}_verifier.sol"

  for fixture in "$name" $(extra_fixtures "$name"); do
    run_fixture "$name" "$fixture"
  done
}

# Register every expected leg up front, so a circuit that dies at compile still
# shows its fixtures as FAILED instead of vanishing from the summary.
for c in "${CIRCUITS[@]}"; do
  for f in "$c" $(extra_fixtures "$c"); do
    PASS[$f]=0
    LEGS+=("$f")
  done
done
TOTAL=${#LEGS[@]}

for c in "${CIRCUITS[@]}"; do
  run_circuit "$c"
done

echo ""
echo "======================================================================"
echo "== SUMMARY"
echo "======================================================================"
for f in "${LEGS[@]}"; do
  if [ "${PASS[$f]}" -eq 1 ]; then echo "  [x] $f  VERIFIED"; else echo "  [ ] $f  FAILED"; fi
done
echo "  verified $OK_COUNT / $TOTAL"

if [ "$OK_COUNT" -eq "$TOTAL" ]; then
  echo "U2 GATE: PASS"
  exit 0
else
  echo "U2 GATE: FAIL"
  exit 1
fi
