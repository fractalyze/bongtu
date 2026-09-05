# Consumer family (no-auditor ops)

bongtu ships two products from one codebase. **Enterprise** is the live arbiter stack: every op
encrypts an authority envelope inside the proof, and a designated arbiter can open every note
([security-model.md](security-model.md)). **Consumer** is a second op family with **no authority
material anywhere** — no arbiter key input, no authority envelope, no arbiter-side KEM: nobody,
bongtu included, can open a consumer note involuntarily. This page states the family's contracts
and guarantees; the full design record — every derivation, budget and rejected alternative — is
[`.dev/op-module-design.md`](../.dev/op-module-design.md) (cited as `OPMOD §n`), which this page
summarizes and does not replace. The consumer wallet app itself (custody, session,
screens) is [wallet.md](wallet.md#the-consumer-wallet-appswallet-web)'s story; this
page owns the protocol family.

Both families share **one pool**: one IMT, one nullifier set, one kKRW escrow. Notes are
**untyped** — the commitment/nullifier algebra is byte-identical across families — so notes
interop freely (an enterprise wallet can spend a note a consumer op minted, and vice versa) and
the anonymity set is shared. Audit semantics are therefore **op-level**, not note-level or
pool-level; what that means is stated honestly in [Audit semantics](#audit-semantics) below.

## The op-module core

Consumer ops enter the pool through a module layer, not new entrypoints. The core `BongtuPool`
keeps everything it owns today — tree, nullifiers, escrow, arbiter epochs
([contracts.md](contracts.md)) — and adds `applyOp` / `applyOpWithPull` / `applyOpWithPush`: an
invariant gate callable only by **registered modules**, enforcing known-root, nonzero-and-unused
nullifiers, nonzero leaves, append-shape exclusivity, and CEI escrow motion on whatever a module
passes (the full invariant list is OPMOD §1.3). Each op family ships as a plain module contract
holding no funds and no consensus state: it wires one verifier, owns one public-signal layout,
injects `enabled` before verify, emits its family's event, and calls `applyOp` for every state
effect. All three variants take the pool's one reentrancy latch. The contract duties — the
gate's error set, the registry, and each module's obligations — are
[contracts.md](contracts.md#the-op-module-layer)'s.

- **Registration is `onlyOwner`, event-logged (`ModuleRegistered`/`ModuleRemoved`), and
  upgrade-equivalent power** — a hostile module is a hostile implementation; the trust boundary
  is the owner key, same as `_authorizeUpgrade`. Users approve the core (the escrow holder,
  whose address never changes), never a module.
- **The six enterprise entrypoints are byte-untouched and never route through `applyOp`** —
  locked, so the live family's verification path is unchanged by construction.
- Every `applyOp` emits `OpApplied`, the audit anchor tying each tree mutation to the module
  that caused it; the indexer cross-checks every consumer op event against it
  ([indexer.md](indexer.md#consumer-op-family-the-module-event-stream)).

The module layer reaches an existing pool as ONE UUPS `upgradeToAndCall` carrying
`reinitializeV3(modules)`; profiles and deployment order:
[deployment.md](deployment.md#deploy-profiles-and-the-consumer-module-family).

## The five circuits

`depositPriv`, `transferPriv`, `transfer10x2Priv`, `withdrawPriv`, `disbursePriv256` (plus
`disbursePriv`, the 1×16 dev-loop arity) — each a sibling derivation of a vendored enterprise
base, parent untouched. Per-file provenance and deltas:
[zeto-derivation.md](zeto-derivation.md#the-consumer-no-auditor-family); exact public-signal
layouts: OPMOD §2. The deprecated `transfer10` gets no consumer twin. Family-wide properties:

- **No authority material.** No `cipherTextAuthority`, no `kemBinding`, no
  `authorityPublicKey` — a consumer proof has no place to name an authority.
- **Hybrid receiver ciphertexts.** Each output's `[value, salt]` ciphertext is keyed by a
  Poseidon fold of the per-output ECDH secret AND a per-output ML-KEM-768 shared secret, under
  new frozen domain tags (`bongtu/consumer-note/v1/*` — the arbiter tags are never reused),
  encrypted at `encryptionNonce + i` (OPMOD §3.3/§3.5). The 1088-byte KEM ciphertexts travel as
  module calldata, event-re-emitted for the small ops and chunk-transported for the batch
  (below). There is no `kemBinding` analogue: a junk encapsulation self-sabotages only the
  sender's own delivery — the recipient's leaf-match rejects the garbage and the note's funds
  are untouched — so nothing plays the arbiter's alarm role.
- **View/spend key split.** Receiver ciphertexts encrypt to a dedicated bjj VIEW key;
  commitments and nullifiers stay bound to the SPEND key. The view identity (`viewPriv` +
  `kemDk`) can discover and decrypt but never spend — the exact shape a later delegated/TEE
  scanner consumes with no protocol change (OPMOD §3.1/§3.7).
- **viewTags.** One public byte per output — the canonical low 8 bits of a tagged Poseidon over
  the ECDH secret, `Num2Bits_strict`-canonical in-circuit — so a scanner skips ~255/256 of
  foreign events before any expensive work (OPMOD §3.2).
- **Every input-side soundness belt survives verbatim** — enabled boolean, value belt,
  zero-commitment guard, `CheckPositive`, `CheckSum`, IMT membership
  ([circuits.md](circuits.md#soundness-invariants) documents them on the enterprise bases;
  OPMOD §2.1 is the per-circuit preservation table). The disburse base's deliberate belt
  omission carries over with its compensating obligation moved into the module: `ZeroNullifier`
  revert first, `enabled = 1` injection second, verify third.

## Discovery is self-scan

There is no `/notes` oracle for consumer notes — no key exists that could build one. A wallet
derives balance and activity from the PUBLIC feed with only its own keys: filter each event's
outputs by viewTag, `Decaps` the survivors, decrypt at `nonce + i`, rebuild the commitment, and
accept iff it equals the on-chain leaf (the leaf-match is the MAC substitute). Normative
pipeline: OPMOD §3.6; the wallet's selfscan mode — cursor-incremental, resumable, "discovery
pending" instead of a silently smaller balance — is summarized in
[wallet.md](wallet.md#indexer-dependency). All three wallet keys (spend, view, KEM) derive from
the ONE MetaMask signature, so recovery stays "re-sign the same struct", and the view/KEM pair
is not computable from the spend key (OPMOD §3.1).

## The public batch path (disbursePriv256)

The enterprise disburse leaves its 256 output commitments recoverable only through the arbiter
envelope, so only an arbiter indexer can serve batch-interior merkle paths. The consumer batch
has no envelope — so it **publishes** them: `receiverCts[1024] ++ viewTags[256] ++
outputCommitments[256]`, one 1536-element calldata array bound by the proof's extended
`disclosureHash` fold, whose commitment run necessarily folds to the proof's `subtreeRoot`
(OPMOD §4.2). ANY indexer — holding no key — fold-verifies the publication and fills the batch,
after which `GET /path/{leafIndex}` serves consumer batch interiors auth-free in both modes
([indexer.md](indexer.md#trust-boundary-arbiter-mode)); a bad publish classifies into the same
alarm statuses as the enterprise disclosure duty
([indexer.md](indexer.md#disclosure-alarms)).

Count-hiding survives publication: pads are full, well-formed value-0 notes with fresh salts and
distinct throwaway owners, so a batch is fixed-shape and a pad is indistinguishable from a
funded output (OPMOD §4.5). The 256 per-recipient KEM ciphertexts exceed one transaction's byte
budget, so a batch is 1 + K transactions: chunk txs keccak-bound to the batch tx's
`kemChunkHashes`, bytes calldata-only — the one documented deviation from logs-only ingest
([indexer.md](indexer.md#consumer-op-family-the-module-event-stream), OPMOD §5). Everything
consensus-relevant is final in the batch tx; a withheld chunk costs at most that chunk's
discoverability-by-scan, never funds.

## The registry triple

Paying a name through a consumer op needs three public keys: the bjj spend pubkey (the existing
`owner`), the note-layer bjj view pubkey (`noteViewPub`), and the ML-KEM-768 encapsulation key
(`kemEk`). The name directory carries the consumer pair as an optional, required-together
extension, bound to the owner's spend-key signature under a versioned digest (v2) that legacy v1
writes can never touch — [indexer.md](indexer.md#name-directory); exact digest forms OPMOD §6.
Registering makes `noteViewPub` public by design (pay-by-name needs it) — which is exactly why
receiver ciphertexts are hybrid: a harvested event plus a public view key must not become
retro-decryptable at a future ECDLP break (OPMOD §5).

## Deploy profiles

Which families a pool serves is its module registration list — owner-controlled, event-logged,
publicly checkable ([deployment.md](deployment.md#deploy-profiles-and-the-consumer-module-family)):

- **audited-only** (the default; byte-identical to the pre-profile deploy): no consumer module
  registered, so every op that exists on the pool is arbiter-disclosable.
- **consumer on the shared pool**: the V3 upgrade + `reinitializeV3(modules)` — both families,
  one anonymity set.
- **consumer-only**: `initializeConsumerOnly` — **no arbiter key exists at all** (no epoch
  minted, no KEM pk hash, no enterprise verifier wired); every enterprise entrypoint reverts and
  the modules are the pool's whole op surface. "No key exists" was chosen over a burned
  placeholder key for honesty: there is nothing to hand over.

## Audit semantics

The precise statement, per family, on one shared pool:

- **Enterprise ops keep issuance-level enforced disclosure, unchanged.** Every enterprise note
  creation and destruction is arbiter-openable from chain data alone
  ([security-model.md](security-model.md#enforced-auditor-disclosure)).
- **Consumer ops have none — for anyone.** No authority key, no escape hatch; a consumer op is
  readable by its recipient (view identity) and known to its sender, and by no one else. That is
  the product, not a gap.
- **The pool-level guarantee is a registration property.** "Everything in this pool is
  auditable" holds exactly on a pool whose owner registers no consumer module — the
  audited-only profile — and that posture is publicly attestable from the
  `ModuleRegistered`/`ModuleRemoved` event stream. On a mixed pool the honest claim is per-op:
  which family an op used is public (the module that emitted it), so an observer can see *that*
  consumer ops occurred, never *what* they carried.

Who-sees-what deltas, the post-quantum scope change, and which residual gaps this family moves:
[security-model.md](security-model.md#the-consumer-family-no-auditor-ops).
