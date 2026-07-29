# Toolchain

Exact invocations. circom, snarkjs, circomlib and the powers-of-tau file live **outside** the repo,
and each entry point names its own overrides: `circuits/build/prove_all.sh` reads
`CIRCOM`/`SNARKJS`/`NODE`/`ZETO`/`CIRCOMLIB`/`PTAU`, the deploy scripts read
`NODE`/`FORGE`/`ANVIL`/`CAST` plus their RPC and key vars (and, on the proving paths,
`BONGTU_NODE_MODULES` below). Only `NODE` is shared — moving to a new
machine means setting several, not one.

## Binaries and roots

```sh
CIRCOM='/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom'   # 2.2.2 — direct exec fails, ld shim required
SNARKJS='node --max-old-space-size=16000 /home/a41/Workspace/zkx-snap/circuits/node_modules/.bin/snarkjs'
NODE=/home/a41/.nvm/versions/node/v22.17.1/bin/node           # v22.17.1
FORGE=/home/a41/.foundry/bin/forge                            # 1.7.1 (anvil, cast alongside)
PTAU=/home/a41/Workspace/zkx-snap/circuits/ptau/pot22_hez.ptau  # BN254, 4.8 GB; 2^22 covers every circuit
ZETO=/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits
CIRCOMLIB="$ZETO/node_modules"
```

The **node-side** scripts get `snarkjs` at runtime from `BONGTU_NODE_MODULES` via
`packages/core/src/extern.ts` (`loadSnarkjs`) — no workspace declares it for that path, so on another
machine set the env var. The call sites are the proving paths `deploy/live/lib/proof_toolbox.ts` and
`deploy/live/giwa_transfer10x2_e2e.ts`, the two circuit gates
`circuits/gates/assert_attacks_throw.ts` and `circuits/gates/auditor_decrypt_check.ts`, and
`contracts/test/fixtures/gen_realproofs.ts`. The `circuits/fixtures/gen_*.ts` fixture generators are
*not* on this path: they import only `@bongtu/core` and node builtins, so `build/prove_all.sh` runs
without it. Chain access everywhere is viem, an ordinary dependency. The browser apps are separate:
`apps/wallet-web` declares `snarkjs` as an ordinary dependency, bundled by Vite. `pot15_hez` is too
small — `transfer` alone is ~62K constraints.

## Include resolution roots

`build/prove_all.sh` passes `-l "$ZETO" -l "$CIRCOMLIB" -l lib`. Which root resolves which include —
and why self-containment comes from the include *spelling*, not the search order — is owned by
[circuits.md](circuits.md#structure-and--l-resolution).

## Per-circuit pipeline

```sh
cd circuits
$CIRCOM <name>.circom --r1cs --wasm --sym -o out/ -l "$ZETO" -l "$CIRCOMLIB" -l lib
$SNARKJS r1cs info                    out/<name>.r1cs
$SNARKJS groth16 setup                out/<name>.r1cs "$PTAU" out/<name>.zkey
$SNARKJS zkey export verificationkey  out/<name>.zkey out/<name>.vkey.json
$SNARKJS zkey export solidityverifier out/<name>.zkey out/<name>_verifier.sol
$NODE out/<name>_js/generate_witness.js out/<name>_js/<name>.wasm inputs/<name>.json out/<name>.wtns
# ^ the WASM path is the REFERENCE for tests and CPU proving. The prover service
#   computes production witnesses from a compiled circuit .so instead —
#   pipeline: circuits/build/build_witness_so.sh, service design: prover/README.md,
#   byte-identity gate against this WASM path: circuits/build/wtns_compare.py.
$SNARKJS groth16 prove  out/<name>.zkey out/<name>.wtns out/<name>.proof.json out/<name>.public.json
$SNARKJS groth16 verify out/<name>.vkey.json out/<name>.public.json out/<name>.proof.json   # prints OK
```

`bash build/prove_all.sh` runs exactly this for deposit / disburse / transfer / withdraw and copies each
verifier into the committed `circuits/verifiers/`. `out/` is gitignored and regenerated each run.

**disburse256 is not in that loop**: multi-minute CPU setup, 1.3 GB zkey, GPU proving. Regenerate it
with the same commands through `zkey export solidityverifier`, then prove on GPU0 with rabbitsnark —
recipe and GPU hygiene rules are in the repo `CLAUDE.md`.

Contract build/test invocations are owned by [`contracts/README.md`](../contracts/README.md); `$FORGE`
above is the binary those commands need on PATH.

## Parity constant

Every layer's Poseidon must agree. The gate value (`contracts/test/fixtures/poseidon_ref.txt`,
asserted by `contracts/test/Poseidon.t.sol`):

```
Poseidon([1,2]) == 7853200120776062878684798364095072458815029376092732009249414926327459813530
```
