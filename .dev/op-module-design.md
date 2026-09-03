# Op-module core + consumer (no-auditor) op family — design spec

Design record, 2026-09-03. Status: **spec only — no code exists for any surface below.**
Format precedent: `.dev/pq-envelope-design.md` (U-P0). Section numbers here are cited as
`OPMOD §n`; the retired v1 spec's `SPEC §n` numbering (`.dev/spec-decisions.md`) is unrelated
and continues to mean that document.

Locked decisions this doc implements and does not relitigate:

- **Two products, one codebase.** Enterprise = the LIVE arbiter stack, unchanged and canonical
  (Base Sepolia pool `0x2a72fea8e97fF79069B3D0165A5DB1Fef7F9322C`). Consumer = a new no-auditor
  op family added beside it.
- **Single pool.** One IMT, one nullifier set, one kKRW escrow. Audit semantics are OP-LEVEL
  and notes are UNTYPED: the commitment/nullifier algebra is byte-identical across families
  (`Poseidon([value, salt, spendPub.x, spendPub.y])` / `Poseidon([value, salt, spendPriv])`,
  `packages/core/src/note.ts:46,55`), so notes interop freely and the anonymity set is shared.
- **Op-module core.** The core owns tree/nullifiers/escrow/arbiter-epochs and exposes an
  `applyOp()` invariant gate restricted to registered modules; each op family ships as a module
  contract (verifier + public-signal layout + event). Registration = `onlyOwner` + event —
  upgrade-equivalent power. Hybrid migration: the six existing enterprise entrypoints stay
  in-core untouched; the module layer arrives in ONE UUPS `upgradeToAndCall` (precedent:
  `reinitializeV2` at `contracts/src/BongtuPool.sol:439`).
- **Consumer circuit family (5 tops):** `depositPriv`, `transferPriv`, `transfer10x2Priv`,
  `withdrawPriv`, `disbursePriv256`. transfer10 is deprecated
  (`packages/client/src/spendFlow.ts:14`) and gets NO consumer twin.
- **No authority material in consumer circuits**: no `authorityPublicKey` public input, no
  `cipherTextAuthority`, no arbiter-side KEM, no arbiter `kemBinding`.
- **Note-layer view/spend split**: receiver ciphertexts encrypt to a dedicated bjj VIEW key;
  commitments and nullifiers stay bound to the SPEND key.
- **Hybrid receiver cts**: fold an ML-KEM-768 shared secret into each consumer receiver-ct key,
  under NEW domain tags (never the arbiter tags in `packages/core/src/kem.ts:54-59`).
- **disbursePriv256 publishes all 256 output commitments**, bound by an extended
  disclosureHash-style fold, so a PUBLIC indexer can fill batch-interior merkle paths (today
  arbiter-only: `apps/indexer/src/tree.ts:173` `fillBatch`, `apps/indexer/src/api/routes/path.ts`).
- **Registry triple**: the indexer name registry extends to
  (bjj spendPub, bjj viewPub, ML-KEM-768 encapsulation key).
- **Discovery**: wallet self-scan via `trialDecryptEvents`
  (`packages/client/src/balance.ts:76`) + viewTag filter; TEE delegation later on the same
  artifacts (§3.7 carries the one compatibility note; otherwise out of scope).

Numbers: anything not measured is labeled **(est.)**. Measured baselines come from
`docs/circuits.md` (constraints, 2026-07-28) and `docs/performance.md` (gas).

---

## S1. `applyOp` — the core invariant gate

### 1.1 Placement

`BongtuPool` (the core) keeps everything it owns today — the single-frontier IMT
(`_appendLeaf` / `_attachSubtree` / `_insertNode`, `contracts/src/BongtuPool.sol:936-999`),
`knownRoots`, `nullifierUsed`, the kKRW escrow, and the arbiter epoch list — and gains a
module-only external surface. The six enterprise entrypoints (`deposit` :493,
`disburseWithCiphertexts` :550, `transfer` :604, `transfer10` :690, `transfer10x2` :785,
`withdraw` :858) are byte-untouched and never route through `applyOp`.

A module is a plain (non-proxied) contract holding **no funds and no consensus state**: it wires
one verifier, owns one public-signal layout, injects `enabled` from nullifiers before verify
(the same rule the core applies today, `contracts/src/BongtuPool.sol:613-615`), emits its
family's event, and calls `applyOp` for every state effect. A module bug is fixed by deploying
a replacement and swapping registration — never by touching core storage.

### 1.2 Signatures

Three variants, split by escrow motion (deposit pulls, withdraw pushes, everything else moves
no tokens), sharing one effects struct:

```solidity
/// The tree/nullifier effects of one verified op. The MODULE has already
/// verified the Groth16 proof and copied these values out of its own verified
/// public-signal vector; the CORE re-derives nothing from proofs and instead
/// enforces the invariants below on whatever a registered module passes.
struct OpEffects {
    /// Membership root the proof was made against. MUST be a known root when
    /// nullifiers is non-empty; MUST be 0 when it is empty (a rootless mint —
    /// depositPriv — may not smuggle a root claim).
    uint256 root;
    /// Nullifiers to spend. Every entry MUST be nonzero and unused — modules
    /// strip padded (zero) slots before calling; the core does NOT skip zeros
    /// the way _spendNullifier does for the in-core ops.
    uint256[] nullifiers;
    /// Output commitments to append as single leaves, in order. Every entry
    /// MUST be nonzero. MUST be empty when subtreeRoot != 0.
    uint256[] leaves;
    /// Nonzero => attach ONE B-leaf subtree at level LOG_B instead of
    /// appending leaves (the disburse shape). Zero => single-leaf appends.
    uint256 subtreeRoot;
}

function applyOp(OpEffects calldata fx)
    external whenInitialized nonReentrant onlyRegisteredModule
    returns (uint256 startLeafIndex);

function applyOpWithPull(OpEffects calldata fx, address from, uint256 amount)
    external whenInitialized nonReentrant onlyRegisteredModule
    returns (uint256 startLeafIndex);

function applyOpWithPush(OpEffects calldata fx, address to, uint256 amount)
    external whenInitialized nonReentrant onlyRegisteredModule
    returns (uint256 startLeafIndex);
```

`startLeafIndex` is the leaf index of the first appended leaf (or the batch start for a
subtree attach) — modules need it for their events, exactly as `deposit` records `first`
(`contracts/src/BongtuPool.sol:517`) and `disburseWithCiphertexts` records `start` (:564).

### 1.3 Invariants enforced (the full list)

In execution order:

1. **`onlyRegisteredModule`** — `registeredModules[msg.sender]` or revert
   `ModuleNotRegistered(msg.sender)`. This is the whole access story: users never call
   `applyOp`; they call a module, and the module is `msg.sender` here.
2. **Known root** — if `fx.nullifiers.length > 0`: `knownRoots[fx.root]` or revert
   `UnknownRoot(fx.root)` (any-historical-root semantics, unchanged from
   `contracts/src/BongtuPool.sol:73`). If `fx.nullifiers.length == 0`: require
   `fx.root == 0` (a mint claims no membership).
3. **Nullifier nonzero + unused** — for every entry: `nf != 0` (revert `ZeroNullifier`) and
   `!nullifierUsed[nf]` (revert `NullifierAlreadyUsed(nf)`), then `nullifierUsed[nf] = true`.
   Sequential and complete, so an in-transaction duplicate reverts on its second occurrence —
   the same defence the arity-10 ops document (:718-722). Unlike the in-core
   `_spendNullifier` (:930), a zero entry is a revert, not a skip: padding is a circuit-layout
   concern and modules strip it before crossing the boundary.
4. **Leaf nonzero** — every `fx.leaves[i] != 0` or revert `ZeroOutputCommitment` (the
   write-side zero-leaf defence, same rationale as :514); then `_appendLeaf` each in order.
5. **Shape exclusivity** — `fx.subtreeRoot != 0` requires `fx.leaves.length == 0` (revert
   `MixedAppendShape()`); the attach path requires `fx.subtreeRoot != 0` trivially. A subtree
   attach runs `_attachSubtree(fx.subtreeRoot)` (partial-block close + level-`LOG_B` insert,
   unchanged).
6. **Escrow delta consistency** — token motion exists ONLY in the two suffixed variants, moves
   exactly `amount`, and runs AFTER all tree/nullifier writes (CEI, `SafeERC20`, mirroring
   `deposit` :522 and `withdraw` :884):
   - `applyOpWithPull`: `token.safeTransferFrom(from, address(this), amount)`.
   - `applyOpWithPush`: `token.safeTransfer(to, amount)` with
     `to != address(0)` (the module has already range-checked the proof-bound recipient the
     way `withdraw` does at :871).
   The core cannot check `amount` against the proof (it never sees the proof); the invariant
   the core enforces is *structural*: no registered module can move escrow except through
   these two calls, one amount per op, and the plain `applyOp` moves none. That `amount` is
   the module's proof-bound public (`pub[0]`) is a module-correctness obligation, reviewed at
   registration — which is `onlyOwner` and explicitly upgrade-equivalent power (a hostile
   module is a hostile implementation; the trust boundary is the owner key, same as today's
   `_authorizeUpgrade`).

Approval note: users approve the **core** (the escrow holder and the pool address that never
changes), not modules. A registered-but-buggy module could therefore pull from any approver —
covered by the same upgrade-equivalence statement above; there is no weaker registration tier.

### 1.4 Registry storage — appended at the tail

Current trailing storage, verified in `contracts/src/BongtuPool.sol` (the tail-slots block):

| slot order | member | line |
|---|---|---|
| tail−3 | `mapping(uint256 => bytes32) public arbiterKemPkHash` | :1010 |
| tail−2 | `ITransfer10Verifier public transfer10Verifier` | :1013 |
| tail−1 | `ITransfer10x2Verifier public transfer10x2Verifier` | :1016 |
| tail | `uint256[47] private __gap` | :1021 |

New state goes AFTER `transfer10x2Verifier`, taking words off the gap (the standing rule,
`docs/contracts.md` § Proxy and wiring):

```solidity
/// OPMOD §1: the module registry. True => the address may call applyOp*.
/// Registration is onlyOwner and upgrade-equivalent power.
mapping(address => bool) public registeredModules;

uint256[46] private __gap;   // was 47: one word consumed
```

One mapping, one word. No enumerable array (module addresses are recoverable from
`ModuleRegistered`/`ModuleRemoved` events, and the indexer/deploy record carries them; an
on-chain array would cost a second slot for nothing the events do not already give).

Management:

```solidity
function registerModule(address module) external onlyOwner whenInitialized;   // revert ZeroModule on 0
function removeModule(address module) external onlyOwner whenInitialized;
```

### 1.5 Events

Core-side (module-side family events are in S2/S4):

```solidity
event ModuleRegistered(address indexed module);
event ModuleRemoved(address indexed module);
/// One per applyOp*: the audit trail tying a tree mutation to the module that
/// caused it. Carries the resulting root so the indexer's per-insert mirror
/// assertion (docs/indexer.md § Mirror invariant) has the same anchor the
/// low-level Appended/SubtreeAppended events give it.
event OpApplied(
    address indexed module,
    uint256 startLeafIndex,
    uint256 nullifierCount,
    uint256 leafCount,        // 0 for a subtree attach
    uint256 subtreeRoot,      // 0 for single-leaf appends
    uint256 root
);
```

`Appended` / `SubtreeAppended` keep firing from `_appendLeaf` / `_attachSubtree` unchanged —
the indexer's tree feed is family-blind by construction.

New errors: `ModuleNotRegistered(address)`, `MixedAppendShape()`, `ZeroModule()`.

### 1.6 Reentrancy vs the existing `_locked` latch

The core has one latch: `uint256 private _locked` at `contracts/src/BongtuPool.sol:277`, with
`nonReentrant` (:279-284) on every op and `whenInitialized` running first. All three `applyOp*`
variants take the **same** latch — no second latch, no module-side latch:

- **Module → core is one crossing.** A user calls `module.transferPriv(...)`; the module
  verifies the proof (view call into its verifier, no state), then calls `applyOp` exactly
  once. The latch is taken at `applyOp` entry, so all consensus writes and the token move
  happen inside it.
- **Cross-family reentry is closed.** An ERC-777-style token callback during
  `applyOpWithPull`'s `safeTransferFrom` finds `_locked == 2` and cannot reenter `deposit`,
  `transfer`, …, nor any `applyOp*` — one latch guards both families because both families'
  state lives in one contract.
- **Module recursion is closed — for NESTED calls only.** A module (or a chain
  module→module) attempting a second `applyOp` while the first is still on the stack reverts
  `Reentrancy`. The latch does NOT constrain sequential calls: a module entrypoint that calls
  `applyOp`, returns, and calls it again in the same transaction succeeds twice — each call
  takes and releases the latch independently. "One user op == one `applyOp`" is therefore a
  reviewed MODULE obligation (registration = upgrade-equivalent review, S1.3), not a
  core-enforced invariant; what the core enforces is that every individual `applyOp` call —
  however many a module makes — independently satisfies the full S1.3 invariant list.
- **Modules stay latch-free deliberately.** They hold no state worth guarding, and a module
  latch would add a second lock ordering to reason about. The verifier call they make before
  `applyOp` is `view`; nothing observable happens before the core latch is taken except proof
  verification, which is idempotent.

---

## S2. Consumer public-signal layouts

Conventions carried over from `docs/circuits.md` § Public surfaces: circom orders public
signals as circuit **outputs first** (declaration order), then top-level `public` inputs
(declaration order); the module indexes the vector literally, so a reorder is a breaking
change requiring a new verifier and a module swap.

Shared design points (derivations in S3):

- `ecdhPublicKey[2]` stays: one ephemeral bjj key per op, ECDH'd per-output against each
  recipient's **view** pubkey (not the spend key — the view/spend split).
- `cipherTexts[nOut][4]` stays: `SymmetricEncrypt(2)` of `[value, salt]` per output, now under
  the hybrid receiver key (S3.3) with per-output nonce `encryptionNonce + i` (S3.5).
- `viewTags[nOut]` is NEW: one field element per output, constrained in-circuit to the range
  `[0, 256)` (S3.2), declared as the last output run.
- **Absent in every consumer circuit** (vs its enterprise twin): `cipherTextAuthority[·]`,
  `kemBinding`, `authorityPublicKey[2]`. `kemSs` remains a **private** witness — now one pair
  of limbs per output (receiver-side), not one per op (arbiter-side) — and surfaces in no
  public signal: a junk receiver KEM ct self-sabotages only the note the sender chose to send
  (the recipient's leaf-match acceptance in `trialDecryptEvents` rejects garbage), so nothing
  plays the alarm role `kemBinding` plays for the arbiter.

Module entrypoint shapes (each module owns exactly one):

```solidity
depositPriv     (a,b,c, uint[16] pub, bytes[] kemCiphertexts)                      // ConsumerDepositModule
transferPriv    (a,b,c, uint[20] pub, bytes[] kemCiphertexts)                      // ConsumerTransferModule
transfer10x2Priv(a,b,c, uint[36] pub, bytes[] kemCiphertexts)                      // ConsumerTransfer10x2Module
withdrawPriv    (a,b,c, uint[16] pub, bytes[] kemCiphertexts,
                 bytes32 stealthEphemeralPub, uint8 stealthViewTag)                // ConsumerWithdrawModule
disbursePriv256 (a,b,c, uint[8]  pub, uint256[] disclosure, bytes32[] kemChunkHashes) // ConsumerDisburseModule (A-chunked, S5)
```

`kemCiphertexts` is one 1088-byte entry per **funded receiver ct** (S3.4); the stealth
announcement pair on `withdrawPriv` mirrors `withdraw`'s calldata-carried, non-proof-bound
announcement (`contracts/src/BongtuPool.sol:858-866`). disbursePriv256 carries no kem ct
bytes in its batch tx — they arrive in K separate chunk transactions keccak-bound to the
batch tx's `kemChunkHashes` (S5, Option A-chunked; the txpool byte cap forbids the single-tx
shape).

### depositPriv — `uint[16]` (enterprise deposit: `uint[19]`)

0-in / 2-out mint. Gains per-output receiver ciphertexts (enterprise deposit publishes an
authority envelope only, so a consumer deposit can mint directly to a third party and the
recipient discovers it by scan).

| idx | signal | output/input |
|---|---|---|
| 0 | `out` (sum of output values; the amount pulled) | output |
| 1..2 | `ecdhPublicKey[2]` | output |
| 3..10 | `cipherTexts[2][4]` (receiver-decryptable, one per output) | output |
| 11..12 | `viewTags[2]` | output |
| 13..14 | `outputCommitments[2]` | public input |
| 15 | `encryptionNonce` | public input |

Absent vs enterprise deposit (`docs/circuits.md`): `cipherTextAuthority[10]` (idx 3..12),
`kemBinding` (13), `authorityPublicKey[2]` (17..18). Added: `cipherTexts[2][4]`, `viewTags[2]`.

### transferPriv — `uint[20]` (enterprise transfer: `uint[37]`)

2-in / 2-out.

| idx | signal | output/input |
|---|---|---|
| 0..1 | `ecdhPublicKey[2]` | output |
| 2..9 | `cipherTexts[2][4]` | output |
| 10..11 | `viewTags[2]` | output |
| 12..13 | `nullifiers[2]` | public input |
| 14 | `root` | public input |
| 15..16 | `enabled[2]` (module-injected: `nullifier[i] != 0`) | public input |
| 17..18 | `outputCommitments[2]` | public input |
| 19 | `encryptionNonce` | public input |

Absent vs enterprise transfer: `cipherTextAuthority[16]` (10..25), `kemBinding` (26),
`authorityPublicKey[2]` (35..36). Added: `viewTags[2]`.

### transfer10x2Priv — `uint[36]` (enterprise transfer10x2: `uint[68]`)

10-in / 2-out — the consolidation + payment workhorse, same rationale as the enterprise arity
(`docs/circuits.md` "outputs, not inputs, are what a spend pays for").

| idx | signal | output/input |
|---|---|---|
| 0..1 | `ecdhPublicKey[2]` | output |
| 2..9 | `cipherTexts[2][4]` | output |
| 10..11 | `viewTags[2]` | output |
| 12..21 | `nullifiers[10]` | public input |
| 22 | `root` | public input |
| 23..32 | `enabled[10]` (module-injected) | public input |
| 33..34 | `outputCommitments[2]` | public input |
| 35 | `encryptionNonce` | public input |

Absent vs enterprise transfer10x2: `cipherTextAuthority[31]` (10..40), `kemBinding` (41),
`authorityPublicKey[2]` (66..67). Added: `viewTags[2]`.

### withdrawPriv — `uint[16]` (enterprise withdraw: `uint[27]`)

2-in / 1-out + proof-bound public recipient. Gains a receiver ct for the **change note**
(enterprise withdraw has none — its change is arbiter-recoverable; the consumer sender must be
able to recover change from chain scan alone).

| idx | signal | output/input |
|---|---|---|
| 0 | `out` (= `sum(inputs) − change`, the ERC-20 amount pushed) | output |
| 1..2 | `ecdhPublicKey[2]` | output |
| 3..6 | `cipherTexts[1][4]` (the change note) | output |
| 7 | `viewTags[1]` | output |
| 8..9 | `nullifiers[2]` | public input |
| 10 | `root` | public input |
| 11..12 | `enabled[2]` (module-injected) | public input |
| 13 | `outputCommitments[0]` (the change note) | public input |
| 14 | `encryptionNonce` | public input |
| 15 | `recipient` (L1 payout address; module range-checks uint160 and pays it, never msg.sender — relayable, mirroring :871) | public input |

Absent vs enterprise withdraw: `cipherTextAuthority[13]` (3..15), `kemBinding` (16),
`authorityPublicKey[2]` (24..25). Added: `cipherTexts[1][4]`, `viewTags[1]`.

### disbursePriv256 — `uint[8]` (enterprise disburse256: `uint[11]`)

1-in / 256-out. The 256 output commitments, receiver cts and viewTags do NOT ride in the
public vector (256 extra publics ≈ +1.56M verifier gas (est.)); they travel in the
`disclosure` calldata array, totally ordered and bound by the extended fold (S4).

| idx | signal | output/input |
|---|---|---|
| 0..1 | `ecdhPublicKey[2]` | output |
| 2 | `disclosureHash` (the EXTENDED fold, S4.2) | output |
| 3 | `subtreeRoot` | output |
| 4 | `nullifiers[0]` | public input |
| 5 | `root` | public input |
| 6 | `enabled[0]` (module-injected constant 1 after a ZeroNullifier check, mirroring :578-586) | public input |
| 7 | `encryptionNonce` | public input |

Absent vs enterprise disburse256: `kemBinding` (4), `authorityPublicKey[2]` (9..10). The
`disclosureHash` name is kept but its preimage changes (S4.2) — the two circuits' folds are
domain-separated by construction because their element counts and content classes differ and
each verifier only ever meets its own family's proofs.

### 2.1 Invariant preservation across the base edits

The five consumer tops are EDITS of the four enterprise bases (strip authority material, add
receiver cts + viewTags). Every input-side soundness constraint of `docs/circuits.md`
§ Soundness invariants is load-bearing and MUST survive each edit verbatim — none is implied
by the additions, and deleting any one reopens a documented mint-from-nothing
(`docs/security-model.md` § Why the zero-commitment guard exists: the index-keyed IMT makes
`0` a genuine, membership-provable leaf, so the upstream `CheckHashes` zero-commitment escape
is a permissionless drain without the guard).

Per consumer circuit, the constraints that must survive (base line numbers are today's, from
the `docs/circuits.md` invariant table):

| consumer circuit (base edited) | `enabled` boolean | value belt `(1−enabled[i])·inputValues[i]===0` | zero-commitment guard `enabled[i]·IsZero(inputCommitments[i])===0` | `CheckPositive` (`GreaterEqThan(100)`: every output value < 2^100) | `CheckSum` conservation |
|---|---|---|---|---|---|
| depositPriv (`deposit_authority_imt_base`) | n/a (0-in) | n/a | n/a | REQUIRED (:79) | REQUIRED (`out` == Σ output values) |
| transferPriv / transfer10x2Priv (`anon_enc_nullifier_non_repudiation_imt_small_base`) | REQUIRED (:103–104) | REQUIRED (:103–104) | REQUIRED (:117) | REQUIRED (:83) | REQUIRED |
| withdrawPriv (`check-nullifiers-value-imt-base`) | REQUIRED (:109–110) | REQUIRED (:109–110) | REQUIRED (:123) | REQUIRED (:86) | REQUIRED |
| disbursePriv256 (`anon_enc_nullifier_non_repudiation_imt_base`) | ABSENT today — see exception below | ABSENT today — see exception below | REQUIRED (:129) | REQUIRED (:87) | REQUIRED |

(depositPriv has no input side; its complement is `applyOp`'s rootless-mint rule — S1.3 #2
requires `fx.root == 0` when `fx.nullifiers` is empty.)

**The disburse-base exception is a REQUIRED module behavior, not an accident.** The disburse
base omits the boolean + belt pair; per `docs/circuits.md` that omission is sound ONLY
because the caller reverts `ZeroNullifier` on a zero nullifier and THEN injects
`enabled[0] = 1` unconditionally (today `contracts/src/BongtuPool.sol:578-586`). For the
consumer family that compensating behavior moves into `ConsumerDisburseModule`: the S4.3
sequence — `ZeroNullifier` revert first, `enabled = 1` injection second, verify third — is a
contract-level obligation of that module, reviewed at registration like every other
module-correctness obligation (S1.3). A module that injects `enabled = 1` without the
zero-nullifier revert hands a zero-leaf spend full trust; one that instead derives
`enabled = (nullifier != 0)` against a belt-less base reopens the
`{nullifier: 0, value: X, enabled: 0}` inflation the belt exists to kill. If a base edit ever
ADDS the belt to the consumer disburse base, this obligation relaxes to the ordinary
derived-`enabled` rule — until then it is load-bearing.

**Gate obligations.** The attack-gate suite (`circuits/gates/*`) re-runs against every new
base before any consumer verifier ships:

- `circuits/gates/test_zero_leaf_unsat.sh` — extends to all four consumer SPENDING circuits
  (transferPriv, transfer10x2Priv, withdrawPriv, disbursePriv256): the
  `(commitment=0, value=X, enabled=1, genuine zeros-membership)` witness MUST throw on the
  guard; the honest fixture MUST prove.
- `circuits/gates/assert_attacks_throw.ts` — the value-belt fixtures (`*_mint`, `*_attack`,
  padded-honest) re-target the consumer tops that carry the belt (transferPriv,
  transfer10x2Priv, withdrawPriv). Its kemBinding-tamper half does NOT apply — no consumer
  circuit has a `kemBinding` public — and is superseded by the consumer-specific gates below.
- NEW consumer-specific gates:
  - **receiver-decrypt parity** — the S3.6 pipeline round-trips every circuit's real
    artifacts (prove → viewTag filter → Decaps → decrypt → leaf-match) for funded AND pad
    outputs, pinning circuit and TS derivations equal;
  - **commitment-publication binding** — tamper any `disclosure` element of a
    disbursePriv256 fixture → the S4.2 fold mismatches `disclosureHash`; tamper the
    `disclosureHash` or `subtreeRoot` public → `groth16 verify` fails;
  - **viewTag canonicality** — a witness asserting the alternate `tagField + p`
    decomposition (S3.2) MUST be unsatisfiable, and TS-vs-circuit tag equality holds on
    random and alias-edge vectors.

---

## S3. Wire formats

### 3.1 View-key derivation — one seed, two scalars (plus one KEM keypair)

The wallet's one seed is the MetaMask EIP-712 signature over the key-derivation struct
(`packages/client/src/derive.ts:66-91`) — deterministic per (account, pool, chainId, version).
Today it yields one scalar (`scalarFromSignature`, :100-110). It extends to:

```
sig        = eth_signTypedData_v4(...)                                  # the one seed (65 bytes)
spendPriv  = keccak256(sig) mod L                                       # UNCHANGED — every live key survives
viewPriv   = keccak256(bytes(sig) ‖ ascii("bongtu/view-key/v1")) mod L  # NEW bjj view scalar
kemSeed    = keccak256(bytes(sig) ‖ ascii("bongtu/consumer-kem/v1/d"))
           ‖ keccak256(bytes(sig) ‖ ascii("bongtu/consumer-kem/v1/z"))  # 64 bytes
(kemEk, kemDk) = ML-KEM-768.KeyGen_internal(kemSeed)                    # @noble/post-quantum keygen(seed)
```

`L` = the BabyJubJub subgroup order (`SUBGROUP_ORDER`), same reduction and same ~2^-252
zero-rejection as the spend path. All three derive from the one signature, so recovery stays
"re-sign the same struct"; and `viewPriv`/`kemDk` are not computable FROM `spendPriv` (they
hang off the raw signature, behind keccak), so handing the view pair to a delegated scanner
never leaks spend authority.

`WalletIdentity` (`packages/client/src/derive.ts:35`) extends:

```ts
export interface WalletIdentity {
  keypair: Keypair;            // bjj SPEND keypair — unchanged
  compressedPubkey: string;    // spend receive address — unchanged
  viewKeypair: Keypair;        // NEW: bjj VIEW keypair (viewPriv, viewPub = viewPriv·Base8)
  compressedViewPubkey: string;
  kemKeypair: { ek: Uint8Array /*1184B*/, dk: Uint8Array /*2400B*/ };  // NEW
}
```

Commitments and nullifiers keep using `keypair` (spend) exclusively — the untyped-note
invariant. The **view identity** = (`viewPriv`, `kemDk`) as a pair: both are needed to decrypt
receiver cts, neither can spend.

Naming note: this note-layer view key is DISTINCT from the stealth meta-address view key
(`packages/core/src/stealth.ts:66-74`, the withdraw/portal DKSAP pair). Both are bjj view
scalars but serve different layers; S6 keeps their registry fields separate.

### 3.2 viewTag derivation — exact

Per output `i`, with `S_i = Ecdh(ephemeralPriv, viewPub_i)` (the circuits' `Ecdh()` gadget ==
`ecdhSharedSecret`, `packages/core/src/note.ts:60`):

```
tagField_i = Poseidon(3)([TAG_VIEWTAG, S_i.x, S_i.y])
viewTag_i  = tagField_i mod 2^8            # the LOWEST 8 bits (bits 0..7 of the
                                           # canonical little-endian encoding)
```

In-circuit: one `Poseidon(3)` + one **`Num2Bits_strict()`** per output (circomlib: 254 bits
+ `AliasCheck`, which pins the decomposition to the canonical one, i.e. the bit string read
as an integer is < p); `viewTags[i]` is constrained to equal the recomposition of bits 0..7,
so the public signal is range-bound to `[0, 256)` AND canonical by construction. Plain
`Num2Bits(254)` is NOT acceptable here: 254 bits reach 2^254 − 1 > p, so every
`tagField_i < 2^254 − p` — roughly a quarter of field elements — admits a second valid
decomposition (`tagField_i + p` as an integer), and p is odd, so the alternate decomposition
flips the low bits: a prover could present the non-canonical bits and publish a wrong tag for
its own recipient. That is silent undiscoverability — the funds are intact but the S3.6
filter drops the event — and while sender self-sabotage is an accepted class elsewhere
(S3.3), here it is closed for ~127 constraints/output (est.), so the strict form is
mandatory. TS side: `poseidonN([TAG_VIEWTAG, S.x, S.y]) & 0xffn` (BigInt arithmetic mod p is
canonical by construction). The TS derivation is pinned equal to the circuit's by test — the
same parity discipline as the `disclosureChain` pin — over random vectors plus crafted
`tagField` values in the alias-sensitive edges (`[0, 2^254 − p)` and `[p − 2^8, p)`); this is
the S2.1 viewTag-canonicality gate.

The tag hashes the **ECDH shared secret only** — deliberately not the KEM secret — so:
(a) it costs no ordering dependency in-circuit, and (b) a scanner holding only `viewPriv`
(no `kemDk`) can still pre-filter, then hand survivors to the decrypting side. Poseidon rather
than keccak (which the stealth layer's tag uses, `packages/core/src/stealth.ts:136-137`)
because this tag must be recomputed inside a bn128 circuit.

Filter power: a wrong-recipient event survives the tag with probability 2^-8, so scan work
drops ~256× before any sponge decrypt; false positives are then killed by the existing
commitment-vs-leaf acceptance (`packages/client/src/balance.ts:76` `trialDecryptEvents`).

### 3.3 Hybrid receiver-ct key — NEW domain tags

Domain-separation tags follow the `kem.ts` convention exactly — `sha256(ASCII) mod r`
(r = the BN254 scalar field), computed 2026-09-03, to be frozen as literals in circuits +
`@bongtu/core`. They are NEW strings; the arbiter tags
(`bongtu/pq-envelope/v1/{key0,key1,binding}`, `packages/core/src/kem.ts:50-59`) are never
reused:

```
TAG_RK0     = sha256("bongtu/consumer-note/v1/key0")    mod r
            = 15911670041651909454486960207337169366505934455020053916031847212914070689294
TAG_RK1     = sha256("bongtu/consumer-note/v1/key1")    mod r
            = 18959445568053998966444410456355743824415104493789084861475706421378089710793
TAG_VIEWTAG = sha256("bongtu/consumer-note/v1/viewtag") mod r
            = 4236837455644426462098222144565872234823396873019476831333450393757091506254
```

Per funded output `i` (sender side; symmetric for the recipient with `Decaps`):

```
S_i         = Ecdh(ephemeralPriv, viewPub_i)                    # bjj, per-output
(ct_i, ss_i) = ML-KEM-768.Encaps(kemEk_i)                       # per-output, fresh
kemSs_i     = kemSsToLimbs(ss_i)                                # two LE-uint128 limbs, kem.ts:79
rk_i[0]     = Poseidon(5)([TAG_RK0, S_i.x, S_i.y, kemSs_i[0], kemSs_i[1]])
rk_i[1]     = Poseidon(5)([TAG_RK1, S_i.x, S_i.y, kemSs_i[0], kemSs_i[1]])
cipherTexts[i] = SymmetricEncrypt(2)([value_i, salt_i], key <== rk_i, nonce <== encryptionNonce + i)
```

Same shape as the arbiter hybrid key (`docs/protocol.md` § The hybrid envelope key) with the
per-output `kemSs_i[2]` limbs as private witnesses and `Num2Bits(128)` limb hygiene, minus the
binding output: there is no arbiter to alarm, and a junk encapsulation self-sabotages only the
sender's own delivery (the leaf-match test rejects the garbage decrypt; the note's *funds* are
untouched — the commitment binds the spend key regardless of ct quality). No per-output
`kemBinding` public signal exists.

Zero-value pad outputs (transfer change-less slots, disburse pads) get the full construction
against a **throwaway** identity (fresh random viewPub point; KEM per S5's scope decision), so
funded and pad outputs are wire-indistinguishable.

### 3.4 Per-recipient `kemCiphertext` transport

Mirroring the arbiter transport (calldata arg + event re-emit,
`docs/contracts.md` § Events: "the arbiter reads logs, not transactions"):

- **Calldata**: `bytes[] calldata kemCiphertexts`, one entry per output that carries a funded
  receiver ct, in output order. The module reverts `WrongKemCiphertextLength(i, got, 1088)`
  unless every entry is exactly `KEM_CIPHERTEXT_LEN == 1088` bytes, and
  `WrongKemCiphertextCount` unless the count equals the circuit's output arity (2 for
  depositPriv/transferPriv/transfer10x2Priv, 1 for withdrawPriv; disbursePriv256 per S5).
  Content is not on-chain-verifiable — same trade-off as the arbiter ct, minus even the
  binding alarm (see 3.3).
- **Event**: each small-op module event re-emits the array, so a scanner reads logs alone:

```solidity
event DepositedPriv(uint256 firstLeafIndex, uint256 oc0, uint256 oc1, uint256 amount,
    uint256[2] ecdhPublicKey, uint256[4] ctReceiver0, uint256[4] ctReceiver1,
    uint256[2] viewTags, uint256 encryptionNonce, uint256 root, bytes[] kemCiphertexts);
event TransferredPriv(uint256[2] nullifiers, uint256[2] outputCommitments,
    uint256[2] ecdhPublicKey, uint256[4] ctReceiver0, uint256[4] ctReceiver1,
    uint256[2] viewTags, uint256 encryptionNonce, uint256 root, bytes[] kemCiphertexts);
event Transferred10x2Priv(uint256[10] nullifiers, uint256[2] outputCommitments,
    uint256[2] ecdhPublicKey, uint256[8] ctReceivers, uint256[2] viewTags,
    uint256 encryptionNonce, uint256 root, bytes[] kemCiphertexts);
event WithdrawnPriv(uint256[2] nullifiers, uint256 amount, uint256 changeCommitment,
    uint256[2] ecdhPublicKey, uint256[4] ctChange, uint256 viewTag,
    uint256 encryptionNonce, uint256 root, bytes[] kemCiphertexts);
// plus the same WithdrawAnnouncement-shaped pair the enterprise withdraw emits (:257)
```

All ciphertext fields are copied from **verified** public signals; only `kemCiphertexts` (and
the withdraw announcement pair) are free calldata, with the same "can only break discovery"
property. No `epoch` field: consumer events carry no arbiter coupling.

### 3.5 Per-output nonce rule — keep `nonce + i` (U-X3), extended to all five

Decision: every consumer circuit encrypts receiver ct `i` under `encryptionNonce + i`
in-circuit — the U-X3 (§11-8 v1.1) construction of
`circuits/lib/encrypt-outputs-per-output-nonce.circom:51` — including `depositPriv` and
`disbursePriv256`, which in the enterprise family share one nonce across outputs.

Justification:

1. **It kills the two-time-pad class structurally.** The enterprise disburse needs the
   assembly-time `assertDistinctOwnerPubkeys` guard (`packages/core/src/note.ts:116`) because
   its outputs share one nonce; with `nonce + i`, a duplicate recipient — self-send, or a
   consumer batch paying one person twice — reuses no keystream. (With hybrid keys the pad is
   already broken up by the per-output `kemSs_i`, but the rule must not silently depend on
   S5's KEM-scope decision: under the ECDH-only fallback the nonce offset is again the only
   defence.)
2. **The scanner already speaks it.** `trialDecryptEvents` tries `nonce + ctIndex`
   (`packages/client/src/balance.ts` per-slice candidates), so discovery code needs no new
   nonce branch.
3. **Uniformity.** One rule across all five circuits, versus the enterprise family's
   two-regime split that U-X3 had to document per-base.

The 128-bit clamp carries over: `encryptionNonce < 2^128` (client-side `toEncryptionNonce`;
the vendored SymmetricEncrypt's in-circuit `LessThan(252)` is alias-prone on a free field
element and must be treated as advisory — no soundness argument may rest on it),
and `nonce + i` overflows the packing slot only at `nonce ≥ 2^128 − 255` — excluded by the
clamp, same argument as the U-X3 header comment.

### 3.6 Discovery pipeline (normative summary)

A consumer wallet scans `GET /events` (or raw logs): filter events by
`viewTag_i == (Poseidon(3)([TAG_VIEWTAG, viewPriv·ecdhPublicKey]) & 0xff)` per output slice →
for survivors, `Decaps(kemDk, kemCiphertexts[i])` → derive `rk_i` → `poseidonDecrypt(ct_i,
rk_i, nonce + i, 2)` → rebuild `commitment(value, salt, spendPub)` → accept iff it equals the
on-chain leaf. The leaf-match remains the MAC substitute, unchanged from
`packages/client/src/balance.ts`.

### 3.7 TEE compatibility (one note, otherwise out of scope)

Every discovery artifact — `ecdhPublicKey`, ct slices, `viewTags`, `kemCiphertexts`, leaf
commitments — is event/calldata-public, and full decryption needs only the view identity
(`viewPriv`, `kemDk`). A later TEE scanner therefore ingests the same feed with the same keys
and no protocol change; nothing in this design assumes the scanner is the key owner.

---

## S4. disbursePriv256 — the public batch path

### 4.1 The published array — calldata extension, event re-emit

The enterprise disburse publishes `4·B` receiver elements ++ the 1030-element authority
envelope as one `uint256[]` calldata arg (2054 at B=256), length-enforced on-chain and
re-emitted in `DisburseCiphertexts` (`contracts/src/BongtuPool.sol:550-566`). The consumer
module keeps that transport shape and swaps the authority tail for the batch-fill material:

```
disclosure = receiverCts[4·B]  ++  viewTags[B]  ++  outputCommitments[B]
           =      1024         ++     256       ++        256            = 1536 elements
```

Three contiguous runs, each in leaf order from the batch start. Placement is **calldata array
+ event re-emit** (`DisbursedPriv` + `DisbursePrivDisclosure(startLeafIndex, uint256[]
disclosure)`), not event-only: the indexer reads logs today
(`docs/contracts.md` § Events), and calldata-only would force every consumer of the batch onto
`eth_getTransactionByHash`. (The known double-pay lever — `docs/performance.md` § Where the
gas goes — applies here too and stays an S9 option, not the default.)

### 4.2 The extended fold — exact, totally ordered

`disclosureHash` is the same Poseidon(2) fold as today — seeded at 0, one absorption per
element (`disclosureChain`, `packages/core/src/envelope.ts:233`) — over the `disclosure` array
**exactly as laid out above**:

```
dh = 0
for i in 0 .. 4B−1:   dh = Poseidon(2)([dh, receiverCts[i]])        # cts, leaf order, 4 per output
for i in 0 .. B−1:    dh = Poseidon(2)([dh, viewTags[i]])           # tags, leaf order
for i in 0 .. B−1:    dh = Poseidon(2)([dh, outputCommitments[i]])  # commitments, leaf order
disclosureHash = dh
```

The order is total and consensus: receiver cts first (flattened `4i + j`), then all viewTags,
then all commitments; any permutation is a different hash. In-circuit, the SAME
`outputCommitments[256]` witnesses feed (a) the `CheckHashes` note binding, (b) the depth-8
subtree builder whose root is the `subtreeRoot` output, and (c) this fold — so a published
array that matches `disclosureHash` is elementwise equal to the circuit's view of the batch,
and its commitment run necessarily folds to `subtreeRoot`.

The locked wording "receiver cts ++ commitments" names the two mandated runs; the viewTag run
sits between them because tags are per-output discovery material like the cts, and burying
them elsewhere (packed publics) costs verifier gas for nothing. S9 carries this as the one
fold-layout open point.

### 4.3 On-chain enforcement

The module (before verify, mirroring :558-561):

```solidity
if (disclosure.length != 6 * B) revert WrongCiphertextLength(disclosure.length, 6 * B); // 1536 at B=256
```

Length only — re-hashing 1536 elements on-chain is the same non-starter as today's 2054
(`docs/contracts.md` § Enforced disclosure). Then: `ZeroNullifier` check, `enabled` injection
(constant 1), `verifyProof`, `applyOp` with `subtreeRoot = pub[3]`, emit
`DisbursedPriv(nullifier, subtreeRoot, disclosureHash, ecdhPublicKey, encryptionNonce, root,
kemChunkHashes, …)` + `DisbursePrivDisclosure(startLeafIndex, disclosure)`. The kem-ct chunk
transactions and their binding are S5 (Option A-chunked).

### 4.4 Indexer verification — fold(leaves) == subtreeRoot, and the public fill

For every `DisbursePrivDisclosure` the indexer (ANY indexer — no arbiter key involved):

1. Recomputes the §4.2 fold over the published 1536 elements; mismatch vs the proof's
   `disclosureHash` → a `disclosure` alarm, exactly the existing `mismatch` class
   (`docs/indexer.md` § Disclosure alarms). Truncated/absent publishes map onto
   `unverifiable`/`withheld` unchanged.
2. Extracts the commitment run (elements `5B .. 6B−1`) and folds it pairwise up `LOG_B = 8`
   levels with `Poseidon(2)` — a plain Merkle fold, no zeros involved (all 256 slots are real
   nonzero-commitment notes) — and checks **`fold(leaves) == subtreeRoot`** from the
   `SubtreeAppended` event.
3. **Consequence — public batch fill.** On both checks passing, the indexer calls
   `fillBatch(startLeafIndex, leaves)` (`apps/indexer/src/tree.ts:173`) in PUBLIC mode. Today
   that call is arbiter-only because interior leaves are recoverable only by decrypting the
   authority envelope; for a consumer batch the leaves are published, so the fill needs no
   key. `GET /path/{leafIndex}` (`apps/indexer/src/api/routes/path.ts`) then serves real
   batch-interior paths for consumer batches **auth-free**: the gate exists because interior
   siblings were other recipients' non-public commitments, and for a consumer batch they are
   public calldata — the same privacy class as single-append leaves, which are already served
   ungated. The 422 sentinel and the arbiter-mode owner gate remain in force for ENTERPRISE
   batches, distinguished by which event filled the block.

**Canonical-form binding (requirement for the module and this verifier).** `poseidon-lite`
reduces every input mod p silently, so a publisher could emit `x + p` in place of the
circuit's canonical element `x` and still pass both folds after implicit reduction, while the
raw calldata bytes disagree with the proven elements (a byte-comparing consumer — e.g. a
scanner matching a published viewTag slot as uint256 — would silently drop the event: the
same self-sabotage discoverability class §3.2 closes). The §4.3 module and/or this fold
verifier MUST reject any disclosure element `>= p` before folding, upgrading "elementwise
equal" from mod-p equivalence to byte equality.

Check 2 is technically implied by check 1 plus circuit soundness (§4.2), but it is kept as an
independent assertion because it is what makes the *fill* safe: a fill is guarded by
`MirrorTree.path`'s internal fold-to-root assert either way (`tree.ts` backstop), and folding
before filling turns a bad publish into an alarm instead of a 500.

**U5 indexer obligations (U4 review).** Two contract-side facts the U5 indexer work must
build on:

1. **Registry mirror = the event log, now guaranteed balanced.** The indexer's
   `registeredModules` mirror derives from `ModuleRegistered`/`ModuleRemoved` alone (S1.4 —
   no enumerable array on-chain). Since the U4 review, `registerModule`/`removeModule`
   revert on no-op transitions (`ModuleAlreadyRegistered` / `ModuleNotRegistered`), so the
   stream is a balanced add/remove log by construction — the mirror may treat a spurious
   double-add or remove-of-unknown as ingest corruption, not as a state to tolerate.
2. **Chunk watch-set outlives module removal.** `submitDisburseKemChunk` never crosses the
   applyOp gate, so a REMOVED disburse module still accepts chunk submissions and emits
   `DisburseKemChunkAccepted` from its deregistered address (consensus-contained — chunks
   touch no pool state — but real for discovery). The indexer's chunk watch-set MUST keep
   including removed disburse-module addresses until every pending batch of theirs has all
   chunks accepted; only then may the address be dropped from the filter.

### 4.5 Pad slots and count-hiding

A pad slot is a full, well-formed output note: `value = 0`, `salt` drawn fresh at random,
`owner spendPub` = a fresh random bjj point **distinct per slot** (and never reused across
batches), with a fresh throwaway view identity for its ct (S3.3). Nothing about a pad is
structurally special: nonzero commitment (so the write-side `ZeroOutputCommitment` class of
guard holds batch-wide), a real ct, a real viewTag, a real KEM ct under S5's chosen scope.

Count-hiding argument: an observer of the chain (and now of the published commitments) sees a
fixed-shape batch — always 256 commitments, always 1536 disclosure elements, always the same
per-output record shape. Distinguishing a pad from a funded output requires distinguishing
(a) `Poseidon([0, salt, ownerX, ownerY])` from `Poseidon([v, salt', ownerX', ownerY'])` with
fresh random salts/owners — Poseidon preimage hiding; (b) a sponge ct of `[0, salt]` under a
key nobody holds from a ct of `[v, salt']` — sponge keystream indistinguishability; (c) a
viewTag of a throwaway view key from one of a registered key — both are 8 truncated bits of a
Poseidon image of a fresh DDH pair. Distinct owners per pad additionally guarantee that no
two pads share a receiver key, so even under the shared-nonce fallback no two-time pad arises
(with the `nonce + i` rule of S3.5 this is belt-and-braces), and no equal-commitment or
equal-tag artifact ever marks the pad region. **Publishing the commitments therefore does not
weaken count-hiding relative to today**: commitments were already computable-by-arbiter and
were always in the tree; what is new is only *which parties* can read them.

The enterprise per-batch privacy statement (`docs/security-model.md` § Who sees what, "the
number of real recipients is not observable") carries over verbatim; what a consumer batch
gives up vs enterprise is exactly and only what the product intends: there is no party that
can open the envelopes involuntarily.

---

## S5. KEM scope for disbursePriv256

The question: do the 256 receiver cts of a consumer batch each carry an ML-KEM-768
encapsulation (1088 B), or does the hybrid fold apply only to the small ops? All gas figures
below are **(est.)** built on the measured 3,905,519-gas hybrid enterprise batch
(`docs/performance.md`, carried over) and the 16 gas/nonzero-calldata-byte rule the pq design
used (`.dev/pq-envelope-design.md` §4).

Two independent per-tx caps bind, and BOTH must be checked: the 16,777,216 **gas** cap, and
the txpool **byte** cap — Base's sequencer runs op-geth, whose default pool-admission limit
is `txMaxSize = 4 × 32 KiB = 131,072 bytes`; a transaction over it is rejected at admission,
before gas pricing is ever consulted. Today's enterprise batch sits safely under both
(~67 KB: 2054-element disclosure = 65,728 B + one 1088 B kem ct + proof/publics/ABI), which
is why the byte cap has never surfaced in the measured tables.

**Option A — hybrid-all-256.**

| component | figure (est.) |
|---|---|
| kem cts calldata: 256 × 1088 B = 278,528 B @ ~16/B | ~4,456,000 gas |
| in-circuit: 256 × (2×Poseidon(5) + 2×Num2Bits(128)) ≈ 256 × ~860 | ~+220k constraints |
| event re-emit if mirrored (278,528 B @ 8/B) | ~2,228,000 gas (avoided by default, see below) |
| batch total (with §S8's other deltas, no kem event) | **~7.9M gas ≈ ~31k/recipient** |

Gas fits: under the 16,777,216 per-tx cap with ~9M headroom; the constraint delta keeps
disbursePriv256 in the 2^22 domain (S8). Absolute cost at the chain's 0.006 gwei quote:
~4.5M extra gas ≈ **+2.7e-5 ETH ≈ +$0.08/batch at $3000/ETH** (est.).

**Bytes do NOT fit — single-tx Option A is dead on arrival.** One transaction would carry
256 × 1088 B kem cts = 278,528 B + 1536 × 32 B disclosure = 49,152 B + proof/publics/ABI
overhead (~1 KB) ≈ **~330 KB of calldata — ~2.5× the 131,072 B op-geth pool cap**. The pool
refuses it; the gas analysis above never runs. Option A therefore ships **chunked**:

**Option A-chunked (the recommended shape).** One batch = 1 + K transactions:

- **Batch tx** — the S2 `disbursePriv256` entrypoint: proof + `uint[8]` publics + the
  1536-element `disclosure` array + `bytes32[K] kemChunkHashes`. ≈ 51 KB — fits. Everything
  consensus-relevant (nullifier spend, subtree attach, commitments, receiver cts, viewTags)
  is FINAL here; only the kem ct bytes are deferred.
- **K chunk txs** — the kem cts in leaf order at `CHUNK_ARITY = 86` outputs per chunk
  (K = ⌈256/86⌉ = 3: 86 + 86 + 84), each ≤ 86 × 1088 = 93,568 B ≈ 94 KB — fits with margin.

Binding — this is the ONE chosen mechanism (folding chunk commitments into the in-circuit
S4.2 fold is rejected: kem ct bytes are not field elements and are deliberately outside the
proof, exactly as the arbiter's 1088 B ct is today):

1. The sender precomputes `kemChunkHashes[j] = keccak256(chunkBytes_j)` (chunk j's 1088-byte
   entries concatenated in leaf order) and passes the array in the batch tx. The module
   requires `kemChunkHashes.length == K`, stores the array under
   `batchId = startLeafIndex` (the `applyOp` return value — the tree is append-only, so it
   is unique forever), and emits it in `DisbursedPriv`.
2. `submitDisburseKemChunk(uint256 batchId, uint256 chunkIndex, bytes chunkData)` on the
   same module, permissionless (anyone holding the bytes can complete a batch). On-chain
   checks, in order: stored hash array exists (`UnknownBatch`), `chunkIndex < K`
   (`BadChunkIndex`), chunk not already accepted (`ChunkAlreadyAccepted`),
   `chunkData.length == chunkArity(chunkIndex) × 1088` (`WrongKemCiphertextLength`), and
   `keccak256(chunkData) == kemChunkHashes[batchId][chunkIndex]` (`ChunkHashMismatch`). On
   pass: mark accepted, emit `DisburseKemChunkAccepted(batchId, chunkIndex)` — the DATA
   stays calldata-only (no event re-emit), per the transport stance below. keccak over
   ~94 KB ≈ 18k gas; total chunking overhead ≈ 2 extra base fees + 3 hashes + hash-array
   storage ≈ **+~0.1M gas/batch (est.)** over the single-tx figures above.
3. The chunk bookkeeping lives in the module and is **discovery-transport state, not
   consensus state** — S1.1's "no consensus state in modules" rule is about
   tree/nullifiers/escrow and is preserved. A module swap strands only PENDING chunk records
   (operational rule: complete a batch's chunks before any swap).

Indexer assembly + recipient semantics:

- On `DisbursedPriv` the indexer records (batchId, K, kemChunkHashes) and marks the batch
  `kem-pending`. On each `DisburseKemChunkAccepted` it fetches the chunk tx via
  `eth_getTransactionByHash` (the calldata-only stance), re-checks the keccak locally
  (mirror-invariant style; the chain already enforced it), and slots the entries at
  `[chunkIndex · 86, …)`. When all K chunks are accepted, the per-output kem ct array is
  assembled and S3.6 discovery proceeds normally.
- A missing chunk j leaves chunk j's outputs hash-committed but unreadable: recipients
  cannot `Decaps`, so those notes are **undiscoverable-by-scan until the chunk lands** — the
  S3.3 sender-self-sabotage class (funds intact and spendable; the commitment, receiver ct
  and viewTag are already final in the batch tx; out-of-band `(value, salt)` delivery still
  works). Because the hash was committed at batch time, a late chunk is verifiably THE bytes
  the sender chose — nothing can be substituted. The indexer surfaces a batch still
  incomplete past a grace period as `kem-withheld`, an operational status distinct from the
  S4.4 disclosure alarms (nothing on-chain-provable was violated).

**Option B — hybrid-on-small-ops-only (the explicit fallback).** disbursePriv256 receiver
cts stay ECDH-only
(key = `Poseidon(5)` fold over `S_i` with `kemSs_i` fixed to zero — or a 2-arity ECDH-only
tagged fold; either way domain-separated from Option A). Saves the ~4.46M calldata, the ~220k
constraints, and the whole chunk machinery (its batch tx is ~50 KB — byte cap moot). The
exposure it accepts is **worse than the enterprise analogue**: the pq design
deferred per-recipient KEM because recipient pubkeys "are never on-chain" and post-phase-1 not
even inside a breakable envelope (`.dev/pq-envelope-design.md` §1/§9). The consumer registry
breaks that premise — `viewPub` is published in the name directory (S6), so a future ECDLP
break retro-decrypts **every ECDH-only consumer receiver ct from public data alone**
(harvested event + public viewPub), value and salt included. That is precisely the HNDL class
the hybrid story exists to close.

**Option C — mKEM (research).** A multi-recipient KEM amortizes one encapsulation across all
256 recipients (one ct, per-recipient derived secrets). No standardized ML-KEM-based mKEM
exists; FIPS 203 has no multi-recipient mode, and rolling a bespoke construction contradicts
the "boring, standardized PQ" stance the arbiter envelope took. Not adoptable now; the
research pointer stays here for the day a standard exists (potential saving: ~4.4M gas/batch
→ ~17k, i.e. the whole Option A premium).

**Recommendation: Option A-chunked — hybrid-all-256 over 1 + K transactions**, kem ct bytes
carried **calldata-only** (no event re-emit anywhere; the public indexer fetches K + 1 txs
per batch via `eth_getTransactionByHash`, a deliberate, documented deviation from the
arbiter's logs-only rule, saving the ~2.2M event copy). Rationale: the consumer product's PQ
story is the user-locked reason the hybrid fold exists at all; Option B silently exempts the
highest-volume surface (256 of every 260 notes a payroll mints) exactly where the public
registry makes the attack cheapest; and A-chunked's real cost is ~$0.08/batch (est.) and
~31k gas/recipient — still ~44× cheaper per recipient than Zeto's published 1.38M
(`docs/performance.md`). **Fallback: Option B, explicitly retained** — if implementation
review judges the chunk machinery too heavy (the extra module surface, pending-chunk state,
K-tx indexer assembly), or a hard gas/byte budget binds on a target chain, ship Option B
behind the same module interface (the module swap is a registration change, not an upgrade)
and document the ECDH-only exposure in `docs/security-model.md` in the pq section's
honest-scope style. Before freezing K and `CHUNK_ARITY`: MEASURE the target chain's actually
accepted tx size — op-geth's 131,072 B is a pool DEFAULT, not a chain constant; the
sequencer, RPC providers and any alternate ingress may each impose their own limit, and the
binding one is whatever the real submission path accepts.

---

## S6. The registry triple

### 6.1 Format

`NameRecord` (`packages/core/src/indexerApi.ts:516`) today carries
`{ name, owner, viewPub, spendPub, updatedAt }` where `viewPub`/`spendPub` are the **stealth
meta-address** halves (bjj view + secp256k1 spend, `packages/core/src/stealth.ts:66`). The
locked triple (bjj spendPub, bjj viewPub, ML-KEM ek) maps onto it as: bjj spendPub == the
existing `owner` field; two NEW fields carry the note-layer view material:

```ts
export interface NameRecord {
  name: string;
  owner: string;        // compressed bjj SPEND pubkey (packPubkey, 0x + 32B hex) — the triple's first leg
  viewPub: string;      // stealth meta viewPub — UNCHANGED, stealth layer
  spendPub: string;     // stealth meta spendPub (secp) — UNCHANGED, stealth layer
  noteViewPub?: string; // NEW: compressed bjj note-layer VIEW pubkey (0x + 32B hex) — second leg
  kemEk?: string;       // NEW: ML-KEM-768 encapsulation key, 0x + 1184-byte hex (2370 chars) — third leg
  updatedAt: number;
}
```

Both new fields optional-on-read (records registered before the extension lack them; a payer
finding them absent falls back to enterprise-style payment to `owner` with no consumer ct
possible) and required-together-on-write (registering one without the other is a 400 — a
viewPub without an ek, or vice versa, is an unusable half-identity). Size: the kemEk hex is
~2.4 KB; the record stays a trivial row (Postgres `names` table gains `note_view_pub`,
`kem_ek` columns, `apps/indexer/src/names.ts` boot/register queries extend in place).

### 6.2 API extension

- `GET /names/:name` (`nameResolve`, `apps/indexer/src/api/routes/names.ts`) returns the
  extended record unchanged in shape discipline — same route, same 404.
- `POST /names` (`nameRegister` / `handleNameRegister`) accepts the two new fields.
  Validation added to the existing `validateStealthMetaAddress` step: `noteViewPub` must
  unpack to a valid curve point (`unpackPubkey`); `kemEk` must be exactly 1184 bytes of hex
  (`kemHexToBytes` + length check, `packages/core/src/kem.ts:66`) and parse as a well-formed
  ML-KEM-768 encapsulation key under `@noble/post-quantum` (module-lattice range check —
  cheap, and it stops a payer from burning a note against garbage).
- The signature binding extends: `nameBindingField` (`packages/core/src/eddsa.ts:238`)
  grows the two new fields into its digest, so the owner's one signature authorizes exactly
  one full (name, stealth meta, note view, kemEk) mapping — the anti-splice property the
  route header documents stays airtight; the exact digest forms and legacy back-compat are
  §6.4. Client half (`buildNameRegistration` /
  `registerName` / `resolveName`, `packages/core/src/indexerApi.ts`) extends in place.

### 6.3 Authentication / anti-squatting — unchanged by construction

The existing story carries over verbatim (`docs/indexer.md` § Name directory): records are
accepted only under the owner's bjj EdDSA-Poseidon signature over the full payload
(`nameAuthMessage`, domain-separated, `|now − ts| ≤ 300 s` replay window); first-come per
name; same-owner update allowed (this is how an existing name ADDS its consumer triple, or
rotates `kemEk`); transfer does not exist; different owner → 409. The registry stays
**availability-trusted only**: a hostile indexer can withhold a triple, never forge one —
and because `owner` (the spend key) signs, the binding "this view/KEM material belongs to
this spend identity" is attacker-unforgeable even though the directory itself is off-chain.

One consequence worth naming (feeds S5): registering makes `noteViewPub` **public**. That is
the intended consumer UX (pay-by-name with no off-channel key exchange) and the reason S5
recommends hybrid everywhere.

### 6.4 `nameBindingField` back-compat — two digest forms, one write rule

`nameBindingField` today digests `sha256("name|viewPub|spendPub")` (lowercased hex) into a
31-byte-fold field element, wrapped by `nameAuthMessage` under the `bongtu/name-auth-v1`
domain tag (`packages/core/src/eddsa.ts:238`). The extension is versioned, not silent:

- **Canonical 5-field form (v2).** Post-upgrade, every NEW registration or update signs
  `sha256("name|viewPub|spendPub|noteViewPub|kemEk")` — five segments ALWAYS, with explicit
  zero-sentinels when the consumer pair is absent: `noteViewPub = "0x" + 64 zero hex chars`,
  `kemEk = "0x" + 2368 zero hex chars` (the full-width lowercase zero of each field, so
  absence is a signed statement, not an encoding ambiguity). The v2 digest is bound in
  `nameAuthMessage` under a NEW domain tag, `sha256("bongtu/name-auth-v2")` folded the same
  way as v1's — so no v1 signature can verify as v2 or vice versa, regardless of what
  characters a name contains.
- **Which form the server verifies — deterministic, by payload shape.** A payload carrying
  either new key (`noteViewPub`/`kemEk`; required-together per §6.1, else 400) is verified
  as v2 ONLY. A payload carrying neither is verified as v1 ONLY (legacy clients keep working
  unmodified). No dual-try fallback: each payload has exactly one admissible form, and a
  signature valid under the other form is rejected outright.
- **v1 writes are read-only for the new fields.** v1-verified records stay fully valid
  (resolve, same-owner update, anti-squat — all of §6.3) but a v1-verified write can NEVER
  set, change or clear `note_view_pub`/`kem_ek`: the server applies v1 writes to the three
  legacy fields only and leaves the new columns untouched. Rotating or clearing the consumer
  pair requires a v2 signature (clearing = explicitly signing the zero-sentinels).
- **Replay cannot clobber.** A captured legacy v1 registration replayed inside the ±300 s
  window (§6.3) still verifies — as v1, and therefore, by the read-only rule, it re-asserts
  only the legacy triple it already bound and cannot touch a consumer triple the owner added
  in between. (Same-payload replay is otherwise an idempotent rewrite, unchanged from
  today.)

---

## S7. Migration

### 7.1 Storage append list

Exactly one word (S1.4): `registeredModules` mapping appended after `transfer10x2Verifier`
(:1016); `__gap` 47 → 46. Nothing else — modules, verifiers and all consumer state live
outside the core.

### 7.2 `reinitializeV3` payload

Version 2 is consumed (`reinitializeV2`, `contracts/src/BongtuPool.sol:439`); the module
layer ships as:

```solidity
/// One-shot migration payload for the op-module upgrade: registers the initial
/// consumer module set. onlyOwner for the same reason reinitializeV2 is —
/// reinitializer(3) alone is first-come after a bare upgradeTo.
function reinitializeV3(address[] calldata modules) external onlyOwner reinitializer(3) {
    for (uint256 i = 0; i < modules.length; i++) {
        if (modules[i] == address(0)) revert ZeroModule();
        registeredModules[modules[i]] = true;
        emit ModuleRegistered(modules[i]);
    }
}
```

No verifier swap rides in it: the six enterprise verifiers are untouched (their circuits do
not change), so unlike U-P0's migration there is **no atomicity constraint between old proofs
and new verifiers** — enterprise ops keep verifying before, during and after.

### 7.3 Deployment order

1. Build + prove the five consumer circuits; `groth16 setup`; export verifiers/vkeys
   (disbursePriv256 via the CLAUDE.md GPU regen recipe: CPU setup ~2.5 min → ~1.3 GB zkey
   (est., same order as disburse256), witness `.so` + `w2s` rebuild).
2. Deploy the five consumer verifier contracts.
3. Deploy the five module contracts, each constructed over (core proxy address, its verifier).
   Modules are inert until registered — a pre-registration call to any module reverts at
   `applyOp`'s `ModuleNotRegistered`, so this step is unsequenced and safely retryable.
4. Deploy the new `BongtuPool` implementation (applyOp + registry + `reinitializeV3`;
   enterprise entrypoints byte-identical).
5. **ONE** `upgradeToAndCall(newImpl, abi.encodeCall(reinitializeV3, ([m1..m5])))` against
   the live proxy `0x2a72fea8e97fF79069B3D0165A5DB1Fef7F9322C` — the locked hybrid-migration
   single transaction. The pool address, the tree, the nullifier set, the escrow and the
   arbiter epochs are all preserved (the whole point of the module design).
6. Clients/indexer: new ABI fragments for the module events (additive — the enterprise
   dual-ABI ingest pattern, `docs/indexer.md` § Dual-ABI ingest, extends with a third
   fragment set rather than replacing anything); registry columns (S6);
   `apps/indexer/abi/BongtuPool.abi.json` refresh (CI drift-gates it, CLAUDE.md).

Rollback: `upgradeTo` back to the current implementation makes `applyOp` vanish;
`registeredModules` entries become inert storage (the exact `disburseAllowed` retirement
pattern, :86-94); no consumer state needs unwinding beyond notes already minted — which are
ordinary notes the enterprise family can spend, by the untyped-note invariant.

### 7.4 Upgrade-test plan (extend `contracts/test/Upgrade.t.sol`)

The existing suite upgrades to a byte-identical impl and pins state + tail-slot neighbors
(`testUpgradePreservesState`, `testUpgradePreservesKemPkHashAndGapNeighbors`) and the
version slot (`testInitializerVersionIsOneAndCannotRerun`). Extensions:

- **`testUpgradeV3RegistersModulesAndPreservesTail`** — build state (deposit + transfer, the
  existing `_buildState`), `upgradeToAndCall(newImpl, reinitializeV3([stubModule]))`; assert:
  implementation slot moved; `registeredModules(stubModule)` true; ERC-7201 version == 3;
  every existing neighbor pin (root, nextLeafIndex, nullifier, epochs, `arbiterKemPkHash`
  0/1/unminted, `disburseAllowed` via stdstore, both arity-10 verifier slots) still green —
  the new mapping is the first slot after `transfer10x2Verifier`, so these neighbors are the
  witnesses that nothing re-strided.
- **`testApplyOpGate`** — unregistered caller reverts `ModuleNotRegistered`; a registered
  stub module can spend a nullifier + append leaves; second registration-era invariants:
  zero nullifier reverts, used nullifier reverts, zero leaf reverts, `MixedAppendShape`,
  rootless-op-with-root reverts, unknown root reverts.
- **`testApplyOpEscrowCEI`** — a reentrant mock token attempting `deposit`/`applyOp` from its
  transfer hook reverts `Reentrancy` (the shared-latch claim of S1.6).
- **`testEnterpriseOpsSurviveModuleUpgrade`** — post-V3, run a stub-verified `deposit` and
  `transfer` and pin roots against the oracle: the six entrypoints are behaviorally untouched.
- **`testReinitializeV3OnlyOwnerOnce`** — non-owner reverts; second call reverts
  `InvalidInitialization`.

### 7.5 Bytecode budget

Deployed implementation today: **16,889 / 24,576 bytes** (given) — 7,687 bytes of headroom.
The core's additions are three thin external functions over existing internals
(`_appendLeaf`/`_attachSubtree`/`_spendNullifier`-equivalent loops), two registry setters,
one struct, four errors, three events: **~1.5–2.5 KB (est.)**, leaving ~5 KB (est.)
headroom. The five verifiers (~15–20 KB each) and five modules are separate contracts with
their own 24,576-byte budgets each; nothing consumer-sized lands in the core. If a later
addition ever crowds the core, the escape hatch is already structural: new logic goes in a
module, not in the core. Verify with `forge build --sizes` before shipping (the number above
must be re-measured on the actual V3 impl).

---

## S8. Budget estimates

Every number in this section is an **estimate** unless it cites a measured figure. Measured
baselines: `docs/circuits.md` constraint table (2026-07-28) and `docs/performance.md`
(hybrid KDF flat cost +2,533 constraints measured; live gas 2026-09-01; disburse 3,905,519
carried over). Unit estimates used below (all est.): Poseidon(2)/(3) permutation ≈ 240–300
constraints; Poseidon(5) ≈ 300; `Num2Bits(128)` = 128; `Num2Bits(254)` = 254;
`Num2Bits_strict` ≈ 380 (254 + `AliasCheck` ≈ 127); one bjj `Ecdh`
scalar-mul ≈ 2,500; sponge = ~1 permutation per 3 plaintext elements + 1; one Groth16 public
input ≈ 6,100 gas (pq doc §4, measured basis); calldata ≈ 16 gas/nonzero byte, event data
8 gas/byte.

### 8.1 Per-circuit constraint deltas and domains

Removed everywhere: the arbiter hybrid KDF (−2,533, measured flat) + the authority envelope
sponge. Added per output: hybrid receiver KDF (~860) + viewTag (~630: `Poseidon(3)` +
`Num2Bits_strict`, S3.2) — combined ~1,490 (est.); circuits whose enterprise twin lacks
receiver encryption also add the per-output `Ecdh` + sponge (~3,000, est.).

| circuit | enterprise base (measured) | delta (est.) | consumer est. | domain est. |
|---|---|---|---|---|
| depositPriv | deposit 14,127 | −1.0k auth sponge −2.5k KDF +2×(2.5k Ecdh + 0.5k sponge + 1.49k) ≈ **+5.5k** | ~19.6k | **2^15** (was 2^14 — spills one level) |
| transferPriv | transfer 64,394 | −1.5k auth sponge −2.5k KDF +2×1.49k ≈ **−1.0k** | ~63.4k | **2^16, TIGHT** — ~2.1k margin under the 65,536 cap; the enterprise 10-arity margin hazard (`docs/circuits.md`) applies verbatim: measure before freezing, budget for a 2^17 spill |
| transfer10x2Priv | transfer10x2 212,386 | −2.7k auth sponge −2.5k KDF +2×1.49k ≈ **−2.2k** | ~210.2k | 2^18 (49.7k margin grows) |
| withdrawPriv | withdraw 54,320 | −1.2k auth sponge −2.5k KDF +1×(0.5k sponge + 1.49k) ≈ **−1.7k** | ~52.6k | 2^16 |
| disbursePriv256 | disburse256 2,796,719 | −84k auth sponge (1030-elt) −2.5k KDF −124k fold shrink (2054→1536 elts) +256×1.49k ≈ **+171k** | ~2.97M | 2^22 (cap ~4.19M — holds) |

Under the S5 fallback (ECDH-only batch receivers) disbursePriv256 drops the 256×0.86k hybrid
term: ≈ 2.75M (est.), same domain. The dev-loop lesson carries over: like disburse/
disburse256, a consumer disburse base should also instantiate a small dev arity, so budget
**six** new verifier/zkey pairs, not five (est., mirrors the enterprise seven-pair rule).

### 8.2 Per-op calldata/gas deltas (vs the measured live table, hybrid rows)

| op | publics Δ | verifier Δ (est.) | calldata/event Δ (est.) | net vs live measured (est.) |
|---|---|---|---|---|
| depositPriv vs deposit 2,642,328 | 19→16 (−3) | −18k | −1088B arbiter kem ct (−17.4k cd −9k ev) +2×1088B receiver kem cts (+35k cd +18k ev) + applyOp hop ~+5k | **~+15k → ~2.66M** |
| transferPriv vs transfer 2,780,006 | 37→20 (−17) | −104k | kem: −26.4k +53k; hop +5k | **~−70k → ~2.71M** |
| transfer10x2Priv vs 3,063,954 | 68→36 (−32) | −195k | kem: −26.4k +53k; hop +5k | **~−165k → ~2.90M** |
| withdrawPriv vs withdraw 1,716,736 | 27→16 (−11) | −67k | kem: −26.4k +26.4k (1 ct); hop +5k | **~−60k → ~1.66M** |
| disbursePriv256 vs 3,905,519 | 11→8 (−3) | −18k | disclosure 2054→1536 elts (−260k cd −133k ev); −arbiter kem ct −26.4k; +256 kem cts +4,456k cd-only split across K=3 chunk txs +~100k chunk overhead (A-chunked, S5); hop +5k | **~+4.1M → ~8.0M aggregate over 1+3 txs ≈ 31k/recipient (batch tx alone ~3.5M)** (Option B: ~−430k → **~3.5M ≈ 13.7k/recipient**) |

The dominant unchanged term everywhere is the Poseidon tree work (~0.93M/leaf,
`docs/performance.md` § Where the gas goes) — the module layer does not touch it.

---

## S9. Open questions (each with a standing DEFAULT)

- **Fold layout for viewTags (S4.2).** DEFAULT: three contiguous runs
  `cts ++ viewTags ++ commitments`, fold in that total order. Override only if the locked
  "receiver cts ++ commitments" wording is read as strictly two runs — then viewTags append
  to the ct run (`cts ++ viewTags` as one "receiver material" run) with no other change.
- **Disburse kem-ct scope + transport (S5).** DEFAULT: **Option A-chunked** —
  hybrid-all-256, kem ct bytes in K = 3 calldata-only chunk txs (`CHUNK_ARITY = 86`)
  keccak-bound to the batch tx's `kemChunkHashes`; no event re-emit of chunk data. The
  target chain's ACTUALLY accepted tx size must be measured before freezing K and
  `CHUNK_ARITY` (op-geth's `txMaxSize = 131,072 B` is a pool default, not a chain constant).
  Override 1: **Option B** (ECDH-only batch receivers) if implementation review judges the
  chunk machinery too heavy — the standing fallback, exposure documented per S5.
  Override 2: event re-emit of chunk data (+~2.2M gas/batch est.) if the logs-only ingest
  rule is judged inviolable.
- **Small-op kem-ct event re-emit.** DEFAULT: re-emit in the module event (arbiter
  precedent, `docs/contracts.md` § Events); the ~9–18k/op saving of dropping it is not worth
  a second ingest path for the high-frequency ops.
- **`OpApplied` vs relying solely on module events + `Appended`.** DEFAULT: emit `OpApplied`
  (one cheap event buys module attribution for the mirror and for forensics).
- **Module removal semantics.** DEFAULT: `removeModule` exists (`onlyOwner`), takes effect
  immediately, strands nothing (notes are untyped; pending user txs revert
  `ModuleNotRegistered` and can be re-proven against a replacement module unchanged — proofs
  bind no module address).
- **`applyOpWithPull` source.** DEFAULT: `from` is module-passed (the module passes its own
  `msg.sender`); users approve the core. Accepted risk: any registered module can spend any
  approval to the core — covered by registration being upgrade-equivalent (S1.3). Override
  (per-module allowance vaults) only if a weaker registration tier is ever introduced.
- **transferPriv domain margin.** DEFAULT: proceed targeting 2^16 and MEASURE at first
  compile (the ~2.1k margin is an estimate stacked on estimates); if it spills, accept 2^17
  (zkey ~2× — browser proof impact to be measured) rather than shaving the viewTag.
- **Pad KEM material under Option A.** DEFAULT: each pad encapsulates against a freshly
  generated throwaway ek (keypair drawn and discarded at assembly). Override to
  random-1088-bytes only if assembly time for 255 pads ever measures as material
  (encapsulation is sub-ms each, so it should not).
- **Registry `kemEk` validation depth (S6.2).** DEFAULT: length + noble parse on register.
  Override to also test-encapsulate if parse alone proves insufficient against malformed
  keys in practice.
- **Consumer dev-loop arity.** DEFAULT: ship a `disbursePriv` (1×16) dev instantiation of
  the consumer disburse base alongside the 256, mirroring the enterprise pair — six new
  verifier/zkey artifacts total.
- **`viewPub` privacy of the public registry (S6.3).** DEFAULT: accepted — pay-by-name
  requires it, and S5's hybrid-everywhere recommendation is the compensating control. Any
  future "unlisted" mode (off-channel triple exchange) changes no protocol surface, only
  distribution.
- **Enterprise entrypoints ever routing through `applyOp`.** DEFAULT: never — locked. Noted
  only so no future refactor "simplifies" the hybrid split away.
