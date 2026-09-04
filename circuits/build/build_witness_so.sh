#!/usr/bin/env bash
# Build the in-process witness calculators the prover service loads (U-P5).
#
# For each circuit: circom --mlir (the fractalyze/circom MLIR backend) ->
# prime-ir-opt -field-to-llvm -> mlir-translate -> llc -> cc -shared, emitting
#   out/lib<name>.so        the compiled witness calculator (~2min per circuit)
#   out/<name>_w2s.json     the witness-index -> signal-index map circom writes
# next to the other gitignored artifacts. The prover service (prover/) holds
# both resident and computes a disburse256 witness in ~1s — ~7x faster than the
# node/WASM calculator it replaced, with an elementwise-identical witness
# vector (prover/README.md owns the byte-identity gate).
#
#   cd circuits && bash build/build_witness_so.sh                # every registry circuit (4)
#   cd circuits && bash build/build_witness_so.sh disburse256    # just one
#
# Toolchain (env-overridable, defaults = this dev box):
#   CIRCOM_MLIR   the fractalyze/circom fork binary (tip 3d1efee3) BUILT WITH the
#                 block-store fix in compiler/src/intermediate_representation/
#                 store_bucket.rs — the unpatched tip stores only element 0 of
#                 array arguments to anonymous components ('Poseidon(4)(in)'),
#                 which Zeto uses pervasively => silently WRONG hashes. Until the
#                 fix is upstreamed, build from the patched checkout.
#   BAZEL_BIN     the rabbitsnark-py bazel output base the three LLVM/MLIR
#                 tools below default into. Its md5 path segment is ONE
#                 workspace's — on any other checkout the default is wrong, so
#                 print yours with `bazel info output_base` in the
#                 rabbitsnark-py checkout and append /bazel-out/k8-opt/bin.
#   PRIME_IR_OPT / MLIR_TRANSLATE / LLC
#                 reused from the rabbitsnark-py bazel output base (LLVM
#                 21.0.0git, prime_ir pin 08220ad via r1cs-solver d82213fd).
#   LLC_MCPU      the -mcpu llc targets (default `native`, i.e. THIS box's
#                 feature set baked into the .so). The prover service loads the
#                 .so at boot, so a .so built here and deployed to an older CPU
#                 SIGILLs the worker on its first compute — set e.g.
#                 `LLC_MCPU=x86-64-v3` when building for another machine.
#   ZETO          the Zeto circuits checkout (same -l roots as build/prove_all.sh).
#
# build/witness_rt/ holds the bongtu-vendored r1cs-solver runtime MLIR (types /
# helpers / circom_runtime) — see the provenance headers there for the two
# deliberate patches (prime_ir 'false' parser workaround, signed comparisons).
set -euo pipefail

cd "$(dirname "$0")/.."   # circuits/build -> circuits (the -l lib root + out/)

# The patched fork checkout lives as a sibling of this repo (uncommitted
# store_bucket.rs fix on top of fractalyze/circom 3d1efee3).
CIRCOM_MLIR="${CIRCOM_MLIR:-$(dirname "$PWD")/../circom-mlir/target/release/circom}"
BAZEL_BIN="${BAZEL_BIN:-/data/a41/bazel/18c5bdb845f2d62f5aff5639ece1ca36/execroot/rabbitsnark/bazel-out/k8-opt/bin}"
PRIME_IR_OPT="${PRIME_IR_OPT:-$BAZEL_BIN/external/prime_ir/tools/prime-ir-opt}"
MLIR_TRANSLATE="${MLIR_TRANSLATE:-$BAZEL_BIN/external/llvm-project/mlir/mlir-translate}"
LLC="${LLC:-$BAZEL_BIN/external/llvm-project/llvm/llc}"
CC="${CC:-cc}"
LLC_MCPU="${LLC_MCPU:-native}"
ZETO="${ZETO:-/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits}"

for tool in "$CIRCOM_MLIR" "$PRIME_IR_OPT" "$MLIR_TRANSLATE" "$LLC"; do
  [ -x "$tool" ] || { echo "FATAL: toolchain binary missing/not executable: $tool"; exit 1; }
done

ALL_CIRCUITS=(disburse256 transfer10x2 deposit disbursePriv256)
if [ "$#" -gt 0 ]; then CIRCUITS=("$@"); else CIRCUITS=("${ALL_CIRCUITS[@]}"); fi

mkdir -p out
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for name in "${CIRCUITS[@]}"; do
  echo "== $name: circom --mlir =="
  # --mlir writes <name>.mlir + <name>_w2s.json into the output dir.
  "$CIRCOM_MLIR" --mlir -o "$WORK" -l "$ZETO" -l "$ZETO/node_modules" -l lib "$name.circom"
  [ -f "$WORK/$name.mlir" ] && [ -f "$WORK/${name}_w2s.json" ] || {
    echo "FATAL: $name: circom --mlir did not emit $name.mlir + ${name}_w2s.json"; exit 1; }

  echo "== $name: lower + compile (~2min) =="
  cat build/witness_rt/types.mlir build/witness_rt/helpers.mlir build/witness_rt/circom_runtime.mlir \
    "$WORK/$name.mlir" > "$WORK/$name.combined.mlir"
  "$PRIME_IR_OPT" -field-to-llvm -o "$WORK/$name.lowered.mlir" "$WORK/$name.combined.mlir"
  "$MLIR_TRANSLATE" --mlir-to-llvmir -o "$WORK/$name.ll" "$WORK/$name.lowered.mlir"
  "$LLC" -relocation-model=pic -filetype=obj -mcpu="$LLC_MCPU" \
    -o "$WORK/$name.o" "$WORK/$name.ll"
  "$CC" -shared -o "out/lib$name.so" "$WORK/$name.o"
  cp "$WORK/${name}_w2s.json" "out/${name}_w2s.json"
  echo "== $name: OK -> out/lib$name.so ($(du -h "out/lib$name.so" | cut -f1)) + out/${name}_w2s.json =="
done
