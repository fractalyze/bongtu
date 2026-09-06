# Ct-free enterprise circuits and the dedicated-pool deploy profile — spec

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

Auto-mode note: concerns triaged with the user 2026-09-06; resolutions are recorded
inline in each concern below. One intent-level change of record: the testnet deploy
target moved from 84532 to **Maroo Testnet 450815** (a second, dedicated pool beside
the live consumer pool) — the intent's 84532 wording is superseded by C9's resolution.

## Requirements

- **R1 (MUST).** Ct-free sibling variants exist for the two enterprise bases that publish
  receiver-decryptable ciphertext — the transfer base
  (`lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom`, tops transfer /
  transfer10 / transfer10x2) and the disburse base
  (`lib/anon_enc_nullifier_non_repudiation_imt_base.circom`, tops disburse / disburse256) —
  as additive files. Five new top-level circuits total; every existing circuit file is
  byte-for-byte unchanged.
- **R2 (MUST).** In each variant, no receiver-decryptable ciphertext content exists:
  `EncryptOutputs` / `EncryptOutputsPerOutputNonce` is removed from the constraint system.
  The hybrid authority envelope is untouched — same ECDH + ML-KEM-768 Poseidon(5) fold,
  same frozen `bongtu/pq-envelope/v1/*` tags, same `kemBinding` construction, same
  authority plaintext layout ([docs/circuits.md](../../../docs/circuits.md#the-hybrid-envelope-key)).
- **R3 (MUST).** Each variant's public-signal vector is **index-identical to its parent**:
  the `cipherTexts` runs remain as output signals constrained to zero (`ecdhPublicKey`
  derived directly via `BabyPbk`, still public — the arbiter's classical ECDH half needs
  it). Falsifiable check: the variant verifier's `verifyProof` ABI equals the parent's
  (`uint[37]`/`uint[141]`/`uint[68]`/`uint[11]`), and every non-ct signal sits at the index
  in [.dev/circuit-surfaces.md](../../../.dev/circuit-surfaces.md). Consequence, R5.
- **R4 (MUST).** `BongtuPool` (`chains/evm/src/`) is reused with **zero code change**: same
  implementation bytecode source, same entrypoint ABIs, same events, same
  `disburseCiphertextLen` derivation (the ct-free disburse publish carries its 4·B receiver
  run as zeros, folded into `disclosureHash` exactly as the circuit folds them). Falsifiable:
  the dedicated-pool profile deploys the existing `BongtuPool.sol` artifact unmodified and
  `apps/indexer/abi/BongtuPool.abi.json` does not change.
- **R5 (MUST).** Every input-side soundness invariant survives verbatim in each variant —
  enabled boolean + value belt (transfer base), zero-commitment guard (both bases),
  `CheckPositive`, `CheckSum`, IMT membership
  ([docs/circuits.md](../../../docs/circuits.md#soundness-invariants)) — and the circuit
  attack gates (zero-leaf unsat class) run against the variants, not only the parents. The
  disburse base's deliberate belt omission carries over together with its compensating
  contract obligation (`ZeroNullifier` revert + unconditional `enabled[0] = 1` injection),
  which R4 keeps in place unchanged.
- **R6 (MUST).** deposit and withdraw are reused as-is: neither base publishes a receiver
  ciphertext today (`deposit_authority_imt_base.circom` and
  `check-nullifiers-value-imt-base.circom` emit only the authority envelope), so the
  dedicated pool wires the existing `DepositVerifier` / `WithdrawVerifier` artifacts and
  their committed fixtures with no regeneration. (Deviation from the intent's literal
  "deposit base" wording — flagged in Concerns C6.)
- **R7 (MUST).** Verifier contracts and zkeys are generated for all five variant tops. The
  ct-free disburse256 zkey (GPU recipe, ~2.5 min setup, 1.24 GB) ships with its matching
  witness `.so` + `w2s` pair in the same change (the prover-service boot invariant,
  `circuits/build/build_witness_so.sh`).
- **R8 (MUST).** Committed proof fixtures for the variant family are produced through the
  existing fixture machinery (`circuits/fixtures/fixture_lib.ts`) against the one fixture
  arbiter pair (bjj key == disburse256 `public[9..10]`, KEM key == `realproofs.kemPublicKey`),
  so a default profile deploy accepts them out of the box
  ([docs/deployment.md](../../../docs/deployment.md#the-arbiter-key-is-fixed-at-deploy-and-the-fixtures-are-bound-to-it)).
  Existing fixtures are untouched.
- **R9 (MUST).** A deploy profile stands up the enterprise-dedicated pool from
  `deploy/forge/Deploy.s.sol`: ct-free verifiers in the five affected slots, existing
  deposit/withdraw verifiers in theirs, no consumer module registered (audited-only), own
  arbiter key knobs as today. The default (no knob set) deploy stays byte-identical to
  today's, preserving deployment.md's "byte-identical to the pre-profile deploy" guarantee.
- **R10 (MUST).** Profile record files follow the repo's named-record precedent
  `addresses.<name>.<chainid>.json` (the `addresses.consumer.31337.json` shape; the
  intent's transposed `addresses.<chainid>.<name>.json` spelling is corrected — Concerns
  C7), written through `AddressBook`-style field-named records. `addresses.450815.json`,
  `addresses.84532.json` and `packages/core/src/chain/network.ts` are untouched.
- **R11 (MUST).** A local gate on a fresh anvil proves the profile end to end: profile
  deploy → real proof-carrying deposit → ct-free disburse settles (tree advances, escrow
  moves, `disclosureHash` binding holds with the zeroed receiver run). Exit code is the
  verdict; the gate runs beside, not inside, the existing `deploy_local.sh` / `e2e_m0.sh`.
- **R12 (MUST).** The repo contains everything for a **one-command human deploy** to
  Maroo Testnet (chain 450815): the runbook (env knobs incl. the required off-anvil
  `ARBITER_KEM_PK_HASH` / `ARBITER_KEM_PK`, using a fresh institutional KEM key, not the
  consumer pool's), the profile invocation, and the record-file destination
  `addresses.ctf.450815.json`. The broadcast itself and the record commit are a
  human-executed step; auto mode stops before any live-chain action. The existing
  `addresses.450815.json` (the live consumer pool) and `addresses.84532.json` (retired)
  are never touched.
- **R13 (SHOULD).** One naming scheme spans the family — circuit files, verifier contracts,
  zkey/fixture names, the profile knob value, and the record `<name>` — and is visibly
  distinct from the consumer `Priv` suffix. Proposal in Design; confirmation is a review
  gate item (Concerns C8).

## Design

### Circuits: layout-preserving ct-free variants

The pool indexes public vectors literally and its entrypoints hard-code the vector lengths
(`transfer(uint[37])`, `transfer10(uint[141])`, `transfer10x2(uint[68])`,
`disburse(uint[11])` — `chains/evm/src/BongtuPool.sol`), and `initialize` computes
`disburseCiphertextLen = 4*B + (authPlain + authPad + 1)` in code. Removing the ct slots
from the public vectors therefore **cannot** be a zero-contract-change: it would need new
entrypoint ABIs, new index constants, new events, a new `disburseCiphertextLen`, and a new
indexer ABI. The design that keeps the decided model's "pool reused via deploy profile"
true is **layout preservation**: each variant keeps the parent's exact public surface and
constrains the receiver-ct output signals to zero.

- **Transfer-base variant** (one base file, three tops at arities 2×2 / 10×10 / 10×2):
  drop the `EncryptOutputsPerOutputNonce` component; `ecdhPublicKey <== BabyPbk(ecdhPrivateKey)`
  directly; `cipherTexts[i][j] <== 0`. Everything else — belts, membership, authority
  envelope, `kemBinding`-last ordering — verbatim from the parent. A proof with any nonzero
  value in a ct slot fails verification, so ct-freeness is proof-enforced, not
  convention. The transfer10 top exists solely to fill the pool's mandatory
  `Transfer10Verifier` slot with a ct-free verifier (the circuit stays deprecated for
  clients — the spend-chain deprecation pins are untouched); wiring the stock ct-carrying
  Transfer10Verifier instead would leave a receiver-ct escape hatch on the dedicated pool.
- **Disburse-base variant** (one base file, tops at 1×16 dev and 1×256): drop
  `EncryptOutputs` the same way; the `disclosureHash` fold keeps its 2054-element shape
  (4·B zeros ++ authority ciphertext), so the contract's length check, the event, and the
  indexer's fold-recompute disclosure alarm all work unchanged — the discloser publishes
  zeros in the receiver run and any deviation alarms exactly as today
  ([docs/security-model.md](../../../docs/security-model.md#enforced-auditor-disclosure)).
  The public count stays 11; the subtree gadget and batch attach are untouched.
- Constraint counts drop on every variant (the Poseidon encryption sponges go away), so
  domain sizes can only shrink or hold — the transfer10 2^18 margin hazard
  ([docs/circuits.md](../../../docs/circuits.md)) is not triggered; measure and record the
  new counts anyway.
- Deposit and withdraw need no variant (R6): they are already receiver-ct-free, and the
  intent's byte-for-byte constraint makes reuse strictly better than a no-op copy that
  would force a new trusted setup and fixture churn for identical semantics.
- New bases follow the vendored-derivation pattern of the consumer family: sibling file,
  parent untouched, provenance header, per-file entry in
  [docs/zeto-derivation.md](../../../docs/zeto-derivation.md).

What ct-freeness buys, precisely: the HNDL exposure the intent cites — classical-ECDH-only
receiver ciphertext permanently on-chain (security-model.md, residual gap "Enterprise
receiver ciphertexts are not post-quantum") — is eliminated on a dedicated pool because no
receiver ciphertext content exists at all. The enterprise-disburse two-time-pad residual
(shared nonce across a batch) becomes moot on this family for the same reason. Recipient
discovery moves entirely to the institution's indexer (the `enterprise-indexer-internal`
intent); on-chain, a recipient's note is recoverable only via the arbiter envelope.

### Naming (proposal, R13)

Family suffix `Ctf`: tops `transferCtf.circom`, `transfer10Ctf.circom`,
`transfer10x2Ctf.circom`, `disburseCtf.circom`, `disburseCtf256.circom`; bases
`ctf_transfer_imt_small_base.circom` / `ctf_disburse_imt_base.circom` in `circuits/lib/`;
verifiers `TransferCtfVerifier.sol` etc.; profile knob and record `<name>` = `ctf`
(records `addresses.ctf.<chainid>.json`, `modules` file not applicable — none registered).
Rationale: `Priv` already means "no-auditor consumer"; the ct-free family is still the
audited enterprise family, so it needs a suffix that does not read as a privacy-family
claim.

### Deploy profile and records

A verifier-profile knob on `Deploy.s.sol` (orthogonal to `MODULE_PROFILE`, which the
profile pins to `none`): the standard value deploys today's six verifiers byte-identically;
the ct-free value swaps the five affected verifier deployments for the variant contracts
and writes the named record pair instead of `addresses.<chainid>.json`. Everything else —
Poseidon, token handling, `initialize`, arbiter knobs, `_selfCheck`, the KEM
fail-closed rules (`_resolveKemPkHash`: required off anvil, fixture value refused) — is
shared, not forked. Per-institution keys are the existing `ARBITER_KEY_X/Y` +
`ARBITER_KEM_PK*` overrides; nothing new is invented for key handling.

The local gate (R11) mirrors `deploy_local.sh`'s shape: scratch anvil, profile deploy,
cast read-backs (`B()==256`, verifier getters == record fields, `currentEpoch()==0`), the
committed deposit fixture as smoke, then a ct-free disburse settled against the pool (the
committed-fixture replay pattern the existing 256-disburse gates use). It is a new gate
script so the existing gates stay byte-stable.

The 450815 deploy (R12) reuses the live-testnet runbook shape in
[deploy/README.md](../../../deploy/README.md#deploy-to-the-live-testnet) with the profile
knob added — same RPC/explorer constants as the live consumer deploy (deployment.md's knob
table), same deployer, new pool addresses (the deployer's nonce has advanced, so no
CREATE-address collision with the recorded consumer contracts; addresses still get copied
from the new record by field name, never by pattern). Per deployment.md, a live chain that
runs the fixture-KEM smoke carries one permanent envelope alarm; the runbook directs the
human to prove wiring with the cast read-backs instead of a smoke deposit, or accept the
documented alarm.

### Fixtures, prover, and client wire types

New committed fixtures: witness inputs + real proofs for the five variant tops (the
ct-free disburse256 proof via the GPU recipe), generated through `fixture_lib.ts` so the
one-arbiter-key property stays true by construction, plus the zkey/vkey artifacts and the
disburse256 witness `.so` + `w2s` pair. The prover service and the wallets are **not**
reconfigured in this slice (Non-goals) — the artifacts exist and the boot invariant is
satisfied for whichever future profile loads them. Because the public vectors are
index-identical, `@bongtu/core` wire types and `toWire` need no new shapes; witness
builders for the gate live with the fixtures/gate drivers, additively.

## Non-goals

- Institution-served discovery (indexer internal mode) and the receipt convention — the
  `enterprise-indexer-internal` and `enterprise-receipts` intents.
- Any change to the live Maroo pool (450815), its records, `network.ts`, or any existing
  circuit/verifier/zkey/fixture byte.
- Wallet/payroll-console/prover-service support for the ct-free family (apps are out of
  scope per the intent; the prover gains artifacts, not configuration).
- A smaller-public-vector ("truly stripped") circuit family and the new pool
  implementation it would require.
- Un-deprecating transfer10, consumer-family changes, Solana-rail parity, per-recipient
  KEM on the shared pool, MPC ceremony.
- Executing the 84532 broadcast — human-only step (R12).

## Concerns

Triaged 2026-09-06 (auto-mode run): decisions taken by the user, obligations routed into
plan/review; resolution appended to each item.

- **C1 (blocker — design decision vs issue #10 wording).** "EncryptOutputs stripped" is
  realized as **zero-pinned ct slots with the parent's public layout**, not slot removal.
  This is the only reading under which "pool contract reused with zero code change" is
  true (entrypoints hard-code `uint[37]/[141]/[68]`, literal indices, and the
  `disburseCiphertextLen` formula). Cost: a ct-free disburse still publishes 1024 zero
  calldata elements and transfers still carry 8 zero publics. If the decided model meant
  literal slot removal, this spec's R3/R4 are wrong and the scope grows to a new pool
  implementation + indexer ABI + wire types. Confirm before plan.
  **RESOLVED (user, 2026-09-06): layout preservation with zero-pinned slots. Literal slot
  removal is deferred; if the footprint reduction is ever wanted it is captured as its own
  future intent. R3/R4 stand as written.**
- **C2 (blocker — circuit soundness).** Every variant is a new constraint system: new
  single-party trusted setup (the testnet caveat in
  [docs/security-model.md](../../../docs/security-model.md#testnet-caveats) now covers
  five more zkeys), and the soundness belts must be re-proven on the variants (R5), not
  assumed from the parents. The disburse belt omission's compensating obligation must be
  re-checked against the unchanged contract path.
  **RESOLVED as an obligation: plan must include running the circuit attack gates and belt
  checks against the variants, and re-verifying the disburse compensating contract path.**
- **C3 (blocker — live-pool compatibility).** The profile edits `Deploy.s.sol`, the shared
  deploy path of the canonical pool. The default invocation must remain byte-identical
  (R9); the review gate should diff a default-profile anvil deploy against main.
  **RESOLVED as an obligation: the verify stage diffs a default-profile anvil deploy
  record against one produced from main.**
- **C4 (blocker — trust surface, cite
  [docs/security-model.md](../../../docs/security-model.md#who-sees-what)).** On a ct-free
  pool the recipient loses the only key-only, chain-data-alone discovery path (receiver-ct
  trial decrypt). Discovery and note delivery become fully dependent on the institution's
  arbiter indexer — the arbiter already sees everything, but recipients now cannot see
  their own notes *without* it. This is a deliberate consequence of the #10 model, but it
  widens the "discovery liveness depends on the indexer" residual gap into a hard
  dependency and must be stated in the security model when this ships. Human sign-off on
  accepting that posture for the enterprise product.
  **RESOLVED by the issue #10 record: institution-served discovery as the ONLY path is the
  decided model itself, and the receipt convention (the enterprise-receipts intent) is the
  recipient's institution-independent exit hatch. Remaining obligation: the
  security-model.md statement in Docs debt.**
- **C5 (policy — testnet arbiter keys, intent open question).** Proposal: keep the fixture
  **bjj** half (Deploy.s.sol default — every committed fixture binds to it; a fresh bjj
  key forces a full fixture regen for zero confidentiality gain, as the envelope key mixes
  the KEM secret) and use a fresh institutional **KEM** half off anvil (mandatory —
  `_resolveKemPkHash` refuses the fixture). Decide whether the testnet pool should instead
  carry a fully fresh institution keypair, which re-proves all new fixtures against it.
  **RESOLVED (user, 2026-09-06): the proposal stands — fixture bjj half, fresh
  institutional KEM half at deploy time.**
- **C6 (scope note).** The intent says ct-free variants of "the four enterprise bases"
  including deposit; in the tree, the deposit and withdraw bases publish no receiver
  ciphertext (authority envelope only), so R6 reuses them unchanged. Confirm against the
  issue #10 record that "deposit base" did not mean something beyond the repo's shape.
  **RESOLVED: verified in-tree (no EncryptOutputs machinery in either base); the intent's
  "four bases" wording overcounted. R6 stands.**
- **C7 (naming precedent).** The intent writes `addresses.<chainid>.<name>.json`; the
  actual repo precedent is `addresses.consumer.31337.json`, i.e.
  `addresses.<name>.<chainid>.json`. The spec follows the precedent (R10). Flag in case
  the transposition was intentional.
  **RESOLVED: the transposition was not intentional; the repo precedent governs.**
- **C8 (naming, intent open question).** The `Ctf` scheme is a proposal; confirm or
  replace at the spec gate so plan/build do not churn renames.
  **RESOLVED (user, 2026-09-06): `Ctf` confirmed.**
- **C9 (policy — chain choice).** 84532 (Base Sepolia) is documented as retired ("no
  longer a live target", deployment.md); deploying the enterprise pool there revives it as
  a live target for this pool only. Docs must say so; confirm the chain choice stands.
  **RESOLVED (user, 2026-09-06): the target moves to Maroo Testnet 450815 — a second,
  dedicated pool on the chain the live consumer pool already runs on, which is what the
  named-record convention exists for. No retired chain is revived; 84532 stays untouched.
  R12 and Design updated accordingly; the intent's 84532 wording is superseded.**
- **C10 (sequencing).** The `deploy-per-chain` intent: whichever lands second rebases; if
  the split lands first, the new records land under `deploy/evm/`. The plan should
  re-check that intent's state at build time.
  **RESOLVED as an obligation: checked at build start (that intent is not yet accepted as
  of 2026-09-06) and re-checked at PR-time rebase.**
- **C11 (ops).** A second resident 1.24 GB disburse zkey and its GPU footprint (~25 GB
  resident service today) may not co-locate with the live family on one GPU. Out of scope
  here (prover config unchanged) but worth recording before `enterprise-indexer-internal`
  builds on it.
  **DEFERRED: recorded for the `enterprise-indexer-internal` intent; no action in this
  slice (the prover gains artifacts, not configuration).**

## Docs debt

When this ships, update:

- `docs/circuits.md` — the ct-free family: table (tops, constraints, publics, domains),
  layout-preservation rule, envelope-unchanged statement.
- `.dev/circuit-surfaces.md` — variant layouts (index-identical, ct runs zero-constrained).
- `docs/zeto-derivation.md` — provenance entries for the two new bases.
- `docs/security-model.md` — dedicated ct-free pool posture: who-sees-what delta (no
  receiver ciphertext, institution-served discovery), the residual-gap scope split
  (receiver-ct HNDL closed on ct-free pools, still open on the shared 450815 pool), C4's
  hardened indexer dependency.
- `docs/deployment.md` — the new profile, named-record convention, the 84532 enterprise
  record, the revived-chain note (C9).
- `deploy/README.md` — profile table row, record file inventory, the new gate, the 84532
  runbook variant.
- `circuits/README.md` — build/prove/gate coverage for the variants.
- `docs/performance.md` — only if the gate work re-measures gas; otherwise no entry.
- `prover/README.md` — a note that ct-free disburse256 artifacts exist and what loading
  them requires (no config change in this slice).
