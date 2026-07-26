# bongtu circuits

The circom toolchain: the four bongtu circuits, their vendored Zeto bases, the
deterministic witness-input generators, and the CPU prove pipeline that gates every
change. Each circuit embeds IMT depth-32 membership (Poseidon-v1) and an in-circuit
authority envelope encrypted to the arbiter key. What each circuit must enforce and
why is owned by [`.dev/spec-decisions.md`](../.dev/spec-decisions.md) §4 (publics) and §5.2 (soundness
belts); per-file Zeto provenance and the deliberate modifications are in
[`docs/zeto-derivation.md`](../docs/zeto-derivation.md).

## The circuits

| file | arity | role |
|---|---|---|
| `deposit.circom` | 0-in / 2-out | stock Zeto Deposit(2) checks + authority envelope over the minted notes |
| `transfer.circom` | 2-in / 2-out | small non-repudiation base; ciphertext rides in the public signals |
| `withdraw.circom` | 2-in / 1-out | withdraw_nullifier rebased onto the IMT + authority envelope over inputs + change |
| `disburse.circom` | 1-in / 16-out | dev-loop batch disburse: subtree gadget (depth-4), `disclosureHash`, authority encryption at seconds-per-iteration scale |
| `disburse256.circom` | 1-in / 256-out | the production headline circuit (~2.79M constraints); same vendored base as `disburse.circom` at depth-8 |

`lib/` holds the vendored bases (`anon_enc_nullifier_non_repudiation_imt_base`,
`check-imt-proof`, and friends) with provenance headers — a fresh checkout builds
with no dependency on any untracked Zeto file. Upstream Zeto sub-checks and circomlib
still resolve from external checkouts via `-l` (paths below).

## Build + prove (the U2 gate)

```sh
cd circuits && bash prove_all.sh    # 4x "snarkJS: OK" and exit 0
```

For each of deposit / disburse / transfer / withdraw: compile → `groth16 setup`
(pot22) → export vkey + solidity verifier → witness from the generated input →
prove → verify. The toolchain is env-overridable (`CIRCOM`, `SNARKJS`, `NODE`,
`ZETO`, `CIRCOMLIB`, `PTAU`) with this dev box's defaults; the exact paths and
per-step invocations are owned by [`docs/toolchain.md`](../docs/toolchain.md). CI
runs the same script with pinned downloads and gates
`git diff --exit-code circuits/verifiers` (drift gate: changing a circuit without
recommitting its verifier fails the build).

- `out/` is **gitignored** (`.zkey` / `.wtns` / `.r1cs` / `*_js/`) and regenerated
  each run.
- `verifiers/` is **committed**: the raw snarkjs solidity exports.
  `contracts/src/verifiers/*.sol` are the same bytes with only the contract renamed
  (e.g. `Groth16Verifier` → `TransferVerifier`).
- `disburse256` is **not** in `prove_all.sh`: its ~1.24 GB zkey takes a multi-minute
  setup and it is proven on GPU (rabbitsnark). The regen recipe after any circuit
  change is the "GPU regen recipe" bullet in the repo [`CLAUDE.md`](../CLAUDE.md);
  the prover service that holds the zkey resident is
  [`prover/`](../prover/README.md).

## Witness-input generators

All generators run on tsx (`npx tsx <file>.ts`), are PRNG-free (fixtures are
byte-reproducible — regenerating leaves a clean tree), share their key material and
helpers through `fixture_lib.ts`, and write committed JSON into `inputs/`:

| generator | writes |
|---|---|
| `gen_inputs.ts` | the four satisfying M0 inputs (`deposit/disburse/transfer/withdraw.json`) from real `ImtTree` membership witnesses |
| `gen_disburse256_input.ts` | `disburse256.json` — the production 1×256 input; also the prover service's boot warm-up proof |
| `gen_attack_inputs.ts` | `withdraw_mint/attack/padded.json` — the §5.2 value-belt attack vectors |
| `gen_zero_leaf_inputs.ts` / `gen_disburse_zero_leaf.ts` | the zero-commitment-belt attack vectors for transfer/withdraw and the disburse base |

## Security gates

Attack fixtures must stay **unprovable** while honest spends stay provable — these
scripts fail loudly if a belt regresses (the exploits they close are documented in
`.dev/spec-decisions.md` §5.2 and `docs/zeto-derivation.md`):

```sh
bash test_zero_leaf_unsat.sh          # zero-commitment belt UNSAT for all 3 spending circuits
npx tsx assert_attacks_throw.ts       # value belt: mint/attack THROW, padded SUCCEEDS
npx tsx auditor_decrypt_check.ts      # deposit/withdraw envelopes decrypt with the arbiter key alone
```

All three need a built `out/` (run `prove_all.sh` first) plus the external snarkjs /
circomlib (`BONGTU_NODE_MODULES`, repo [`CLAUDE.md`](../CLAUDE.md)).

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE). Derived-from-Zeto files keep their
Kaleido copyright headers; circom/snarkjs/circomlib (GPL family) stay external and
un-bundled — see [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
