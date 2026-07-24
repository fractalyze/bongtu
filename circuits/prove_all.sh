#!/usr/bin/env bash
# bongtu M0 Unit U2 gate (spec §4, docs/milestone-m0.md Done#2).
#
# For each of the 4 circuits: compile -> groth16 setup (pot22) -> export vkey +
# solidity verifier -> generate_witness from the JS-produced input.json ->
# groth16 prove -> groth16 verify. Prints "[INFO] snarkJS: OK" four times and
# exits 0 when all four verify. Verifier .sol files are copied into verifiers/
# (committed; they feed U3). Reports r1cs constraint + public-signal counts.
#
#   cd circuits && bash prove_all.sh
#
# Not idempotency-fragile: out/ is regenerated each run; .zkey/.wtns/.r1cs are
# gitignored.
set -uo pipefail

cd "$(dirname "$0")"

CIRCOM='/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom'
SNARKJS="node --max-old-space-size=16000 /home/a41/Workspace/zkx-snap/circuits/node_modules/.bin/snarkjs"
NODE=/home/a41/.nvm/versions/node/v22.17.1/bin/node
ZETO=/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits
PTAU=/home/a41/Workspace/zkx-snap/circuits/ptau/pot22_hez.ptau

mkdir -p out verifiers inputs
# circom emits CommonJS witness helpers (out/<name>_js/generate_witness.js uses
# `require`). The repo root is now an ESM package ("type":"module"), which would
# otherwise make Node treat those generated .js as ESM and fail. Mark the whole
# (gitignored) out/ tree as CommonJS so the generated helpers load unchanged.
echo '{ "type": "commonjs" }' > out/package.json

echo "== regenerating input fixtures =="
$NODE --import tsx gen_inputs.ts || { echo "FATAL: input generation failed"; exit 1; }

CIRCUITS=(deposit disburse transfer withdraw)
declare -A PASS
OK_COUNT=0

run_circuit() {
  local name="$1"
  PASS[$name]=0
  echo ""
  echo "======================================================================"
  echo "== $name"
  echo "======================================================================"

  echo "-- compile"
  $CIRCOM "$name.circom" --r1cs --wasm --sym -o out/ \
      -l "$ZETO" -l "$ZETO/node_modules" -l lib || { echo "$name: compile FAILED"; return; }

  echo "-- r1cs info"
  $SNARKJS r1cs info "out/$name.r1cs" || { echo "$name: r1cs info FAILED"; return; }

  echo "-- groth16 setup"
  $SNARKJS groth16 setup "out/$name.r1cs" "$PTAU" "out/$name.zkey" || { echo "$name: setup FAILED"; return; }

  echo "-- export verification key"
  $SNARKJS zkey export verificationkey "out/$name.zkey" "out/$name.vkey.json" || { echo "$name: vkey export FAILED"; return; }

  echo "-- export solidity verifier"
  $SNARKJS zkey export solidityverifier "out/$name.zkey" "out/${name}_verifier.sol" || { echo "$name: sol export FAILED"; return; }
  cp "out/${name}_verifier.sol" "verifiers/${name}_verifier.sol"

  echo "-- generate witness"
  $NODE "out/${name}_js/generate_witness.js" "out/${name}_js/$name.wasm" "inputs/$name.json" "out/$name.wtns" \
      || { echo "$name: witness generation FAILED"; return; }

  echo "-- groth16 prove"
  $SNARKJS groth16 prove "out/$name.zkey" "out/$name.wtns" "out/$name.proof.json" "out/$name.public.json" \
      || { echo "$name: prove FAILED"; return; }

  echo "-- public signal count: $($NODE -e "console.log(require('./out/$name.public.json').length)")"

  echo "-- groth16 verify"
  if $SNARKJS groth16 verify "out/$name.vkey.json" "out/$name.public.json" "out/$name.proof.json"; then
    PASS[$name]=1
    OK_COUNT=$((OK_COUNT+1))
  else
    echo "$name: verify FAILED"
  fi
}

for c in "${CIRCUITS[@]}"; do
  run_circuit "$c"
done

echo ""
echo "======================================================================"
echo "== SUMMARY"
echo "======================================================================"
for c in "${CIRCUITS[@]}"; do
  if [ "${PASS[$c]}" -eq 1 ]; then echo "  [x] $c  VERIFIED"; else echo "  [ ] $c  FAILED"; fi
done
echo "  verified $OK_COUNT / 4"

if [ "$OK_COUNT" -eq 4 ]; then
  echo "U2 GATE: PASS"
  exit 0
else
  echo "U2 GATE: FAIL"
  exit 1
fi
