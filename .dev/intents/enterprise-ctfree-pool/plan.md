# Ct-free enterprise circuits and the dedicated-pool deploy profile — plan

Spec: [spec.md](spec.md)

Auto-mode run; committed as the branch's second commit (after the accepted spec).
Overlap check at plan time: no other intent run in flight (no other `feat/*` worktree,
no open feature PR touching these files; `deploy-per-chain` is not yet accepted).

## Changes

Ordered work units; one commit per unit via workflow:commit.

### U1 — variant bases and tops (circuits, additive)

Files: `circuits/lib/ctf_transfer_imt_small_base.circom` (new),
`circuits/lib/ctf_disburse_imt_base.circom` (new), `circuits/transferCtf.circom`,
`circuits/transfer10Ctf.circom`, `circuits/transfer10x2Ctf.circom`,
`circuits/disburseCtf.circom`, `circuits/disburseCtf256.circom` (all new).

- Each base is a sibling copy of its parent with a provenance header
  (docs/zeto-derivation.md pattern) and exactly one semantic change: the receiver
  encryption component is gone. `ecdhPublicKey` comes straight from
  `BabyPbk()(ecdhPrivateKey)` (the authority ECDH still needs it public);
  every `cipherTexts[i][j] <== 0`. Transfer base: the `cipherTexts[nOutputs][4]`
  output signals stay outputs, zero-constrained. Disburse base: `cipherTexts` stays the
  internal signal feeding the unchanged `disclosureHash` fold (zeros ++ authority ct).
  Belts, membership, kemBinding-last ordering, authority envelope: verbatim.
- Tops mirror the parents' arities and `public` lists exactly: transferCtf =
  (2,2,32), transfer10Ctf and transfer10x2Ctf = parent arities (read from
  `transfer10.circom` / `transfer10x2.circom` at build), disburseCtf = (1,16,32),
  disburseCtf256 = (1,256,32).

Proof: circuits compile; public-signal counts equal the parents (37 / 141 / 68 / and the
disburse counts); constraint counts recorded and lower than parents (sponges removed).

### U2 — CPU pipeline, fixtures, verifier contracts

Files: `circuits/build/prove_all.sh` (add transferCtf, transfer10Ctf, transfer10x2Ctf,
disburseCtf to ALL_CIRCUITS), `circuits/fixtures/gen_inputs.ts` (ctf fixture inputs:
same witness builders as the parents — the input signal sets are identical),
`chains/evm/src/verifiers/TransferCtfVerifier.sol`, `Transfer10CtfVerifier.sol`,
`Transfer10x2CtfVerifier.sol`, `DisburseCtfVerifier.sol` (new, exported by the pipeline).

Proof: `prove_all.sh transferCtf transfer10Ctf transfer10x2Ctf disburseCtf` legs all
verify; every receiver-ct slot in the produced `public.json` is zero; `git status` shows
NO change to any existing committed verifier or fixture (setup determinism holds).

### U3 — GPU disburseCtf256 artifacts

Files: `chains/evm/src/verifiers/DisburseCtf256Verifier.sol` (new),
`chains/evm/test/fixtures/disburseCtf256.public.json` + proof fixture (new, exact file
set mirrors the parent's committed disburse256 fixtures), witness `.so` + `w2s` pair via
`circuits/build/build_witness_so.sh`.

- CLAUDE.md GPU recipe: compile → groth16 setup (CPU ~2.5 min, 1.24 GB zkey) → export
  verifier/vkey → witness → rabbitsnark GPU prove (timeout ≥ 300000; confirm GPU memory
  back to ~idle after, kill stray prover PIDs).
- DEVIATION (build time): the witness `.so` could not actually be built — the
  circom-mlir toolchain checkout is ABSENT from this box at build_witness_so.sh's
  documented default (`../circom-mlir/target/release/circom` does not exist beside the
  repo), a pre-existing environment gap that equally blocks rebuilding the parent
  disburse256.so from main today. disburseCtf256 is added to the script's registry so
  the pair builds wherever the toolchain exists; the prover service is not reconfigured
  in this slice (spec Non-goals), so the boot invariant is not triggered. Filed as a
  repo issue at PR time.
- Fixture inputs through the existing machinery so the arbiter binding holds:
  `public[9..10]` == the fixture bjj arbiter key (spec C5 resolution).

Proof: GPU proof verifies against the exported vkey; `public[9..10]` equals the parent
fixture's arbiter key; the 4·B receiver run in the disclosure preimage is all zeros.

### U4 — variant tests and attack gates

Files: `chains/evm/test/CtfVerifiers.t.sol` (new; name may fold into the existing test
layout — follow Base.sol conventions), `circuits/gates/assert_attacks_throw.ts` and/or
`circuits/gates/test_zero_leaf_unsat.sh` (extend to the ctf bases — spec C2 obligation).

- Foundry: each committed ctf fixture proof verifies via its verifier contract; a
  tampered proof with a NONZERO receiver-ct slot is rejected (ct-freeness is
  proof-enforced, the R3 falsifiable check); a B=16 pool wired with DisburseCtfVerifier
  settles the disburseCtf fixture (contract path unchanged, zero-nullifier revert and
  enabled-injection intact per R5).
- Attack gates: zero-leaf unsat class runs against both ctf bases.

Proof: `forge test` green including the new suite; attack gate exits 0 on the variants.

### U5 — deploy profile

Files: `deploy/forge/Deploy.s.sol` (VERIFIER_PROFILE knob), `deploy/forge/AddressBook.sol`
(named-record path helper, e.g. `namedPath("ctf")` → `addresses.ctf.<chainid>.json`).

- `VERIFIER_PROFILE=standard` (default): byte-identical behavior to today, writes
  `addresses.<chainid>.json` as before. `VERIFIER_PROFILE=ctf`: the four affected
  slots get TransferCtfVerifier / Transfer10CtfVerifier / Transfer10x2CtfVerifier /
  DisburseCtf256Verifier; MODULE_PROFILE is required to be `none` (audited-only);
  record goes to `addresses.ctf.<chainid>.json`. Arbiter knobs, `_selfCheck`,
  `_resolveKemPkHash` fail-closed rules: shared, untouched.

Proof: new forge script test or gate step deploys both profiles on anvil; the
default-profile record is field-identical to one produced from main (spec C3 obligation,
also re-checked at verify); the ctf-profile record wires the ctf verifier addresses.

### U6 — dedicated-pool local gate

Files: `deploy/gates/ctf_pool_local.sh` (new; name finalized in-branch).

- Scratch anvil → `Deploy.s.sol` with VERIFIER_PROFILE=ctf BATCH_SIZE=256 → cast
  read-backs (B()==256, verifier getters == record fields, currentEpoch()==0) →
  committed deposit fixture smoke (deposit verifier is the unchanged one, R6) →
  committed disburseCtf256 fixture replay settles (tree advances, escrow moves,
  disclosureHash binds the zeroed receiver run). Log-file + exit-code discipline
  (never pipe through tail).

Proof: the gate exits 0 on a clean run; it is the R11 falsifiable end state.

### U7 — runbook, records inventory, docs

Files: `deploy/README.md` (profile row, gate row, the 450815 enterprise runbook:
one-command human deploy with fresh institutional ARBITER_KEM_PK/HASH),
`docs/deployment.md` (profile + named-record convention + the second-pool-on-450815
posture), `docs/circuits.md` (ctf family table + layout-preservation rule),
`docs/security-model.md` (ct-free pool who-sees-what delta, receiver-ct HNDL closed on
dedicated pools / open on shared, institution-served discovery dependency),
`.dev/circuit-surfaces.md` (variant rows), `docs/zeto-derivation.md` (two base entries),
`circuits/README.md` (build/gate coverage), `prover/README.md` (artifacts-exist note).

Proof: docs build nothing, so the proof is the stage-5 review pass against the
Docs-debt list in spec.md.

### Supporting files (review-stage addendum)

The units above under-enumerated the supporting files their proofs ride on; all are
inside spec scope and additive, listed here so the plan matches the shipped diff:
U2 also touches `chains/evm/test/fixtures/gen_realproofs.ts` + `realproofs.json`
(R8's "existing fixture machinery") and the `circuits/verifiers/*_verifier.sol`
raw-export mirrors plus the four committed ctf input JSONs; U3 also touches
`gen_disburse256_oracle.ts` (fixture-set prefix parameter); U4 folds into
`chains/evm/test/VerifierDrift.t.sol` and adds `DisburseCtf256.t.sol`, and extends
`circuits/fixtures/gen_attack_inputs.ts` / `gen_zero_leaf_inputs.ts` /
`gen_disburse_zero_leaf.ts`; U6's gate splits into `ctf_pool_local.sh` +
`ctf_leg.ts` and commits `deploy/addresses.ctf.31337.json` as tracked scratch.

## Risks

- **Regenerating existing artifacts by accident**: prove_all.sh re-runs are
  deterministic, but the check is explicit — after U2/U3, `git status` must show only
  ADDED files under circuits/verifiers mirrors and fixtures; any modified existing
  verifier/fixture is a stop-and-investigate.
- **Deploy.s.sol regression on the canonical path**: caught twice — U5's
  default-profile record diff, and the verify stage repeating it from a clean state.
- **GPU residue**: after U3, confirm GPU memory returns to ~15 MiB idle and no stray
  prover PIDs (CLAUDE.md).
- **Witness .so / zkey mismatch**: build_witness_so.sh runs in the same unit as the
  zkey (U3), never split across commits.
- **Domain-size drift**: constraint counts shrink, so pot22 still covers; record the
  new counts in docs (U7) to keep the transfer10 margin note honest.
- **Worktree isolation**: gates run in this worktree with the recreated
  `node_modules/@bongtu` symlinks (done at workspace setup); `BONGTU_NODE_MODULES` env
  for snarkjs/circomlibjs per CLAUDE.md.
- **PATH**: every gate invocation prefixes the foundry + node PATH export.

## Proving gates

Per iteration (quick): `packages/core` tests + `tsc` + `npm run typecheck --workspaces
--if-present` + `forge test` (chains/evm) + the targeted prove_all legs for whatever
circuit changed.

Final (before PR, via /verify full): `deploy/gates/e2e_m0.sh` (must stay green —
nothing in its path changes), indexer conformance (`cd apps/indexer && npm test` —
ABI untouched so this guards R4), the new `ctf_pool_local.sh` gate, full
`prove_all.sh`, and the U5 default-profile byte-identity diff.
