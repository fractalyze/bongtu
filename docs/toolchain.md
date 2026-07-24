# bongtu toolchain (verified 2026-07-23)

Exact invocations. circom needs the ld-linux shim (nix-built binary); snarkjs and ptau live outside the repo.
M0 uses **CPU proving** (`snarkjs groth16 prove`), NOT the rabbitsnark GPU path (that is M1).

## Binaries

```sh
CIRCOM='/lib64/ld-linux-x86-64.so.2 /usr/local/bin/circom'          # v2.2.2 — direct exec fails, shim required
SNARKJS='node --max-old-space-size=16000 /home/a41/Workspace/zkx-snap/circuits/node_modules/.bin/snarkjs'
ZETO=/home/a41/Workspace/research/disclosure-poc/zeto/zkp/circuits                     # -l root: TRACKED upstream sub-checks (lib/check-*, encrypt-outputs) + node_modules/circomlib
CIRCOMLIB="$ZETO/node_modules"                                                          # -l root: bare circomlib/circuits/*
# ptau (BN254, Hermez): pot22 covers every M0 circuit (biggest ~150K << 2^22)
PTAU=/home/a41/Workspace/zkx-snap/circuits/ptau/pot22_hez.ptau       # 4.8GB; pot15_hez (2^15) too small for transfer(~60K)
FORGE=/home/a41/.foundry/bin/forge                                   # v1.7.1  (anvil alongside)
NODE=/home/a41/.nvm/versions/node/v22.17.1/bin/node                  # v22.17.1
```

## Per-circuit CPU pipeline (M0)

```sh
cd /home/a41/Workspace/research/disclosure-poc/bongtu/circuits
$CIRCOM <name>.circom --r1cs --wasm --sym -o out/ -l "$ZETO" -l "$CIRCOMLIB" -l lib   # lib/ = bongtu-vendored bases + check-imt-proof
$SNARKJS groth16 setup out/<name>.r1cs "$PTAU" out/<name>.zkey                # seconds for small arities
$SNARKJS zkey export verificationkey out/<name>.zkey out/<name>.vkey.json
$SNARKJS zkey export solidityverifier out/<name>.zkey out/<name>_verifier.sol
node out/<name>_js/generate_witness.js out/<name>_js/<name>.wasm input.json out/<name>.wtns
$SNARKJS groth16 prove out/<name>.zkey out/<name>.wtns proof.json public.json
$SNARKJS groth16 verify out/<name>.vkey.json public.json proof.json           # must print OK
```

## Reusable sources (read, don't reinvent)

- ✅ **Provenance (see `docs/zeto-derivation.md`) — VENDORED (Unit 0):** `check-imt-proof.circom` (the IMT
  membership gadget) and `anon_enc_nullifier_non_repudiation_imt_base.circom` (the 256 disburse base) were
  **NOT upstream Zeto** — git-untracked project-authored files living in the zeto checkout. They are now
  vendored into **`bongtu/circuits/lib/`** with provenance headers, and the 256 base additionally carries the
  §5.2 zero-commitment belt. `disburse.circom` / `disburse256.circom` include the vendored base by bare name
  (resolved via `-l lib`), so **a fresh checkout builds `disburse` with no dependency on any untracked zeto
  file** (verified by hiding the untracked files and recompiling). The third untracked file
  `run_nonrep_imt_256.circom` is **superseded by `circuits/disburse256.circom`** (same base + public list) —
  not vendored.
- Sub-checks that STILL resolve into the pinned zeto checkout (TRACKED upstream, byte-identical by
  construction, via `-l $ZETO` / `-l $ZETO/node_modules`): `lib/check-positive.circom`, `lib/check-hashes.circom`,
  `lib/check-sum.circom`, `lib/check-nullifiers.circom`, `lib/encrypt-outputs.circom`, and `circomlib`.
- Other circuits to adapt: `.../lib/check-nullifiers-value-base.circom` (withdraw SMT→IMT rebase points at
  :21/:44/:84 — vendored as `lib/check-nullifiers-value-imt-base.circom`), `.../deposit.circom` (stock 0×2).
- Contract patterns: `../onchain/src/BatchInsertPoolV2.sol` (frontier + root-history + subtree attach — but
  it burns a 256-block per deposit; §5.1 replaces that with incremental single-frontier append),
  `../onchain/test/*.t.sol` (Poseidon parity gate, stub-verifier isolation, gas assertions),
  `contracts/test/fixtures/gen_poseidon.ts` (circomlibjs Poseidon-v1 bytecode → poseidon2.hex).
- Poseidon-v1 reference hash (parity gate): `Poseidon([1,2]) == 7853200120776062878684798364095072458815029376092732009249414926327459813530`.

## Foundry

```sh
cd contracts && forge init --no-git --force .   # first time; foundry.toml needs ffi=true for calldata gen
$FORGE test -vv
```
