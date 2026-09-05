# Contracts

`chains/evm/src/BongtuPool.sol` is the whole consensus surface: one shielded pool holding the
single-frontier IMT, the nullifier set, ERC-20 custody, the arbiter epoch list, six Groth16
verifier calls, and the `applyOp` gate the consumer op modules drive. Everything else in
`chains/evm/src/` is a generated verifier, an interface, a proxy/ownership util, the portal pair
([portal.md](portal.md)), or a consumer op module ([below](#the-op-module-layer)). How to build
and test the folder is owned by [`chains/evm/README.md`](../chains/evm/README.md).

## Entry points

| function | publics | access | tree effect |
|---|---|---|---|
| `deposit(a,b,c,pub,kemCiphertext)` | `uint[19]` | permissionless | appends 2 leaves, pulls `pub[0]` tokens |
| `transfer(a,b,c,pub,kemCiphertext)` | `uint[37]` | permissionless | spends 2 nullifiers, appends 2 leaves |
| `transfer10(a,b,c,pub,kemCiphertext)` | `uint[141]` | permissionless | spends 10 nullifiers, appends 10 leaves |
| `transfer10x2(a,b,c,pub,kemCiphertext)` | `uint[68]` | permissionless | spends 10 nullifiers, appends 2 leaves |
| `withdraw(a,b,c,pub,kemCiphertext,stealthEphemeralPub,stealthViewTag)` | `uint[27]` | permissionless (relayable) | spends 2 nullifiers, appends 1 change leaf, pushes `pub[0]` tokens to the proof-bound `pub[26]` recipient (never msg.sender); emits a paired `WithdrawAnnouncement` |
| `disburseWithCiphertexts(a,b,c,pub,receiverCiphertexts,kemCiphertext)` | `uint[11]` + `uint256[]` | anyone (allowlist retired 2026-07-28) | spends 1 nullifier, attaches a `B`-leaf subtree |

Every op takes the ML-KEM-768 `kemCiphertext` as a trailing `bytes calldata` argument and reverts
`WrongKemCiphertextLength` unless it is exactly `KEM_CIPHERTEXT_LEN == 1088` bytes. It is not
otherwise inspectable on-chain — its correctness is bound off-chain by the proof's `kemBinding`
public signal and the arbiter's decapsulation
([security-model.md](security-model.md#post-quantum-the-hybrid-authority-envelope-key)).

`rotateArbiter` and `_authorizeUpgrade` are `onlyOwner`. Every operation runs
`whenInitialized` before `nonReentrant`, so a call against an uninitialized proxy reverts
`NotInitialized` rather than tripping the latch. ERC-20 moves follow CEI (`SafeERC20`, after the
tree update). The underlying token **must** be non-fee-on-transfer and non-rebasing: the amount is
proof-bound before the pull, so a fee makes the pool insolvent by construction.

## Proof binding

The contract never trusts calldata for the two fields that decide soundness. Before each
`verifyProof` it copies `pub` into memory and overwrites:

| injected field | value | why |
|---|---|---|
| `enabled[i]` | `nullifier[i] != 0` (transfer, transfer10, transfer10x2, withdraw); constant `1` (disburse) | a prover that could set `enabled = 0` on a value-carrying input would skip membership — mint-from-nothing |
| `authorityPublicKey[2]` | `currentArbiterKey()` from storage | a sender that could name the key would encrypt the envelope to itself and silently kill non-repudiation |

A proof made against different values simply fails verification (`InvalidProof`). The circuit-side
belts that make this injection sufficient are in [circuits.md](circuits.md#soundness-invariants).

`kemBinding` is deliberately **not** injected: it is read from the proof's own public signals,
because the contract has nothing to check it against — verifying an ML-KEM encapsulation on-chain is
not affordable. It is the arbiter, not the pool, that closes that loop.

disburse additionally reverts `ZeroNullifier` before verification: its single input is always real,
so `enabled` degenerates to a constant.

## Nullifier spend and root acceptance

- `nullifierUsed[nf]` is a plain `mapping(uint256 => bool)`. `_spendNullifier` skips `nf == 0`
  (a padded, `enabled = 0` input) and reverts `NullifierAlreadyUsed` otherwise.
- `knownRoots[root]` records **every** historical root, including the empty-tree root seeded at
  initialization. `isKnownRoot` is an O(1) lookup and there is no eviction window — an unknown root
  reverts `UnknownRoot`. Double-spend is the nullifier set's job, so accepting an old root costs
  nothing and removes the proof-staleness race that a ring buffer creates on a fast-block L2 where
  both single-leaf appends and batch attaches move the root.

## Enforced disclosure

`disburseWithCiphertexts` is the **only** disburse entry point. A plain, ciphertext-free `disburse`
does not exist in the contract, so publication is a consensus rule and not a convention.

```
require(receiverCiphertexts.length == disburseCiphertextLen)   // else WrongCiphertextLength
disburseCiphertextLen = 4*B + (authPlain padded to 3) + 1
                      = 1024 + 1030 = 2054                     at B = 256
```

`disburseCiphertextLen` is derived in `initialize` from `B`, so it cannot drift from the circuit's
envelope length. The chain checks **length only** — re-hashing 2054 field elements on-chain is not
affordable — while content stays bound by the proof's `disclosureHash` public signal. A
length-padded junk publish still succeeds as a transaction, and yields undecryptable notes plus a
provable `mismatch` alarm from the indexer. That split (chain enforces availability, indexer
enforces correctness) is the honest statement of the guarantee; see
[security-model.md](security-model.md).

deposit, transfer, transfer10, transfer10x2 and withdraw need no such argument: their authority
envelopes ride inside the public-signal vector, so the verifier itself binds them, and the contract
copies those exact words into the event. transfer10 in particular publishes 40 receiver elements
and a 64-element authority envelope that way (transfer10x2: 8 and 31) — bound by the proof, not by
a length rule on free calldata.

## Output commitments

- **Zero output commitments are rejected** on every appending path (`ZeroOutputCommitment`), and on
  transfer10 that means all ten output slots — transfer10x2 both — not just the first: an unused
  slot there is a real value-0 note with a salt, so its commitment is nonzero too.
  A zero leaf is a non-note; appending one would put a value-unbound leaf in the tree, which is
  precisely what the circuit-side zero-commitment guard forbids as a *spend* input. Closing it on
  the write side too is defence in depth (`chains/evm/test/Enforcement.t.sol`).
- **Output uniqueness is deliberately absent.** Upstream Zeto's `validateOutputs` also rejects
  duplicate output commitments. Duplicates share one nullifier, so every copy past the first is
  unspendable — the sender burns their own funds and no one else is affected. It is a self-burn
  foot-gun, not a soundness hole, and the check is not worth its gas on a 256-output batch.

## Events

All ciphertext in events is copied from **verified** public signals, never from free calldata — the
one exception is `DisburseCiphertexts`, whose payload is length-checked and hash-bound instead.

| event | carries |
|---|---|
| `Appended(leafIndex, leaf, root)` | every single-leaf insert (the indexer's tree feed) |
| `SubtreeAppended(startLeafIndex, subtreeRoot, root)` | every batch attach |
| `Deposited` | epoch, first leaf index, both commitments, amount, `ecdhPublicKey`, `uint256[10]` authority envelope, nonce, root, `kemBinding`, `kemCiphertext` |
| `Transferred` | epoch, 2 nullifiers, 2 commitments, `ecdhPublicKey`, 2×`uint256[4]` receiver ciphertexts, `uint256[16]` authority envelope, nonce, root, `kemBinding`, `kemCiphertext` |
| `Transferred10` | epoch, 10 nullifiers, 10 commitments, `ecdhPublicKey`, `uint256[40]` receiver ciphertexts (10x4, leaf order), `uint256[64]` authority envelope, nonce, root, `kemBinding`, `kemCiphertext` |
| `Transferred10x2` | epoch, 10 nullifiers, 2 commitments, `ecdhPublicKey`, `uint256[8]` receiver ciphertexts (2x4, leaf order), `uint256[31]` authority envelope, nonce, root, `kemBinding`, `kemCiphertext` |
| `Withdrawn` | epoch, 2 nullifiers, amount, change commitment, `ecdhPublicKey`, `uint256[13]` authority envelope, nonce, root, `kemBinding`, `kemCiphertext` |
| `Disbursed` | epoch, nullifier, `subtreeRoot`, `disclosureHash`, `ecdhPublicKey`, nonce, root, `kemBinding`, `kemCiphertext` |
| `DisburseCiphertexts(startLeafIndex, receiverCiphertexts)` | the 2054-element array |
| `ArbiterRotated(epoch, keyX, keyY, activatedBlock)` | bjj key rotation |
| `ArbiterKemPkHashSet(epoch, kemPkHash)` | the same epoch's KEM pk hash |

Every op event carries the **epoch index**, so an auditor picks the exact arbiter key even at a
rotation-boundary block. Without `ecdhPublicKey` + `encryptionNonce` no recipient can derive a
decryption key at all, which is why they are in the event rather than off-chain. `kemCiphertext` is
re-emitted rather than left in calldata for the same reason: the arbiter reads logs, not
transactions.

Adding those two fields changed every op event's topic0, which is why a reader must carry both ABI
generations to see the full history ([indexer.md](indexer.md#dual-abi-ingest)).

## Arbiter epochs

`arbiterEpochs` is an append-only array of `{keyX, keyY, activatedBlock}`. `initialize` seeds epoch
0 — the only epoch a fresh pool has — and every later one comes from an explicit `rotateArbiter`.
In-flight proofs built against the previous key become invalid at rotation; there is no grace
window.

The struct is **frozen**: appending a field would re-stride the dynamic array and corrupt live
epochs across an upgrade. So the per-epoch ML-KEM-768 encapsulation-key hash lives in a sibling
`mapping(uint256 => bytes32) public arbiterKemPkHash`, in the tail block of storage that ends in
`uint256[47] __gap`.

`rotateArbiter(newKey, newKemPkHash)` writes both and emits both events. There is no bjj-only
overload, and neither it nor `initialize` accepts a zero hash — so `arbiterKemPkHash[epoch] == 0`
means exactly one thing to a reader: that epoch was never minted. A client that read a zero for a
live epoch would have no way to tell an un-keyed epoch from an unallocated index, and would draw KEM
material against nothing. The full 1184-byte key is distributed off-chain and verified by clients
against this hash ([deployment.md](deployment.md#the-arbiter-key-is-fixed-at-deploy-and-the-fixtures-are-bound-to-it)).

## The op-module layer

The consumer (no-auditor) op family enters the pool through registered **module contracts**, not
new entrypoints; the six enterprise entry points above are byte-untouched and never route through
this layer. Rationale, budgets and rejected alternatives: `.dev/op-module-design.md` §1/§4/§5;
the family narrative: [consumer.md](consumer.md). This section states the contract duties.

### `applyOp` — the invariant gate

Three externals over one `OpEffects` struct (`root`, `nullifiers[]`, `leaves[]`, `subtreeRoot`),
split by escrow motion:

| function | escrow motion |
|---|---|
| `applyOp(fx)` | none |
| `applyOpWithPull(fx, from, amount)` | pulls exactly `amount` from `from` (the deposit shape) |
| `applyOpWithPush(fx, to, amount)` | pushes exactly `amount` to `to` (the withdraw shape); `to != 0` or `InvalidRecipient` |

All three run `whenInitialized nonReentrant onlyRegisteredModule` — the pool's ONE `_locked`
latch, so an ERC-777-style token callback cannot reenter any op of either family; modules are
deliberately latch-free (they hold no state worth guarding, and their pre-`applyOp` verifier
call is `view`). Each returns `startLeafIndex` (the first appended leaf, or the batch start for
a subtree attach) and emits `OpApplied(module, startLeafIndex, nullifierCount, leafCount,
subtreeRoot, root)` — the per-op audit anchor the indexer cross-checks every module event
against ([indexer.md](indexer.md#consumer-op-family-the-module-event-stream)).

The gate enforces, in execution order, on whatever a registered module passes — the core
re-derives nothing from proofs:

1. **non-empty effects** — no nullifiers, no leaves, no subtree is `EmptyOp` (a zero-effect op
   would emit an ambiguous `OpApplied`);
2. **known root iff spending** — `knownRoots[fx.root]` when nullifiers are present; `fx.root ==
   0` when none (a mint claims no membership) — else `UnknownRoot`;
3. **every nullifier nonzero and unused** — `ZeroNullifier` / `NullifierAlreadyUsed`, marked
   sequentially and completely so an in-transaction duplicate reverts on its second occurrence.
   Unlike `_spendNullifier`, a zero entry here is a revert, not a skip: padding is a
   circuit-layout concern and modules strip zero slots before crossing the boundary;
4. **shape exclusivity** — `fx.subtreeRoot != 0` requires empty `leaves` (`MixedAppendShape`);
   the attach runs at level `LOG_B` through the same internals as disburse;
5. **every leaf nonzero** — `ZeroOutputCommitment`, appended in order;
6. **escrow motion last** — CEI, `SafeERC20`, after all tree/nullifier writes, only in the two
   suffixed variants and exactly `amount`. The core never sees the proof, so `amount == pub[0]`
   is a module obligation reviewed at registration.

`Appended` / `SubtreeAppended` keep firing from the shared internals — the indexer's tree feed
is family-blind.

### The module registry

`registeredModules` (one mapping, appended at the storage tail; `__gap` 47 → 46) gates the three
`applyOp*`. Management: `registerModule` / `removeModule`, both `onlyOwner whenInitialized`,
plus `reinitializeV3(modules)` — the one-shot `upgradeToAndCall` payload (`onlyOwner
reinitializer(3)`; no verifier swap rides in it, so unlike the v2 upgrade there is no
old-proof/new-verifier atomicity constraint).

- **No-op transitions revert** (`ModuleAlreadyRegistered` / `ModuleNotRegistered`; `ZeroModule`
  on the zero address; `reinitializeV3` rejects duplicate entries the same way). Why: there is
  no on-chain enumerable array — the `ModuleRegistered`/`ModuleRemoved` event stream is the
  canonical registry reconstruction source, so it must stay a balanced add/remove log; a mirror
  may treat a spurious double-add or remove-of-unknown as ingest corruption, never as state to
  tolerate.
- **Registration is upgrade-equivalent power.** Users approve the core, so a registered module
  can spend any approval made to the core and mint into the shared tree. The trust boundary is
  the owner key, same as `_authorizeUpgrade`; there is no weaker registration tier.
- **Removal takes effect immediately and strands nothing consensus-side**: notes are untyped,
  proofs bind no module address, and a pending user tx re-proves against a replacement module
  unchanged. One non-consensus tail survives removal: `submitDisburseKemChunk` (below) never
  crosses `applyOp`, so a removed disburse module still accepts chunk submissions from its
  deregistered address — indexers keep watching removed disburse-module addresses until every
  pending batch of theirs completes.

### The consumer modules

Six contracts in `chains/evm/src/modules/`, each plain (non-proxied), holding no funds and no
consensus state, constructed over (core, verifier). `ConsumerOpModule` is the shared base:
`KEM_CIPHERTEXT_LEN = 1088` with per-entry length and count checks
(`WrongKemCiphertextLength(index, got, want)`, `WrongKemCiphertextCount` — the count equals the
circuit's output arity, or the scanner's per-output slicing desyncs), zero-slot stripping before
the `applyOp` boundary, and `InvalidProof` / `ZeroPool` / `ZeroVerifier`.

| module | entrypoint | duties beyond the base |
|---|---|---|
| `DepositPrivModule` | `depositPriv(a,b,c, uint[16] pub, bytes[] kemCiphertexts)` | no injection (a 0-in mint has no `enabled` run); verify, then `applyOpWithPull(msg.sender, pub[0])` — the proof-bound pull; emits `DepositedPriv` |
| `TransferPrivModule` | `transferPriv(…, uint[20] pub, …)` | injects `enabled[i] = nullifier[i] != 0` before verify; `applyOp`; emits `TransferredPriv` |
| `Transfer10x2PrivModule` | `transfer10x2Priv(…, uint[36] pub, …)` | the same at input arity 10; emits `Transferred10x2Priv` |
| `WithdrawPrivModule` | `withdrawPriv(…, uint[16] pub, …, stealthEphemeralPub, stealthViewTag)` | range-checks `pub[15]` to a nonzero uint160 (`InvalidRecipient` — the circuit binds a field element and cannot range-check an address); injects `enabled`; `applyOpWithPush(recipient, pub[0])` — relayable, never msg.sender; emits `WithdrawnPriv` plus the calldata-carried `WithdrawAnnouncement` pair |
| `ConsumerDisburseModule` | `disbursePriv256(…, uint[8] pub, uint256[] disclosure, bytes32[] kemChunkHashes)` and `submitDisburseKemChunk(batchId, chunkIndex, chunkData)` | see below |

Every ciphertext field in a module event is copied from **verified** public signals; only
`kemCiphertexts` (and the withdraw announcement pair) are free calldata, with the same "can only
break discovery" property. No `epoch` field: consumer events carry no arbiter coupling.

`ConsumerDisburseModule` is parameterized over the pool's own `B` (read at construction, so a
wiring mismatch is unrepresentable); one code path serves the 1×16 dev twin and the 1×256 batch:

- **Disclosure length and canonical form, before verify**: `disclosure.length == 6·B`
  (`WrongCiphertextLength` — 1536 at B = 256) and every element `< p`
  (`NonCanonicalDisclosureElement`). Poseidon folds reduce mod p silently, so an `x + p` element
  would pass the off-chain fold while its raw bytes disagree with the proven element; rejecting
  `>= p` upgrades the fold's elementwise equality from mod-p equivalence to byte equality.
- **The `ZeroNullifier`-then-inject obligation**: the disburse base omits the enabled boolean
  and value belt, so the module MUST revert `ZeroNullifier` first and only then inject
  `enabled = 1` unconditionally, then verify — injecting without the revert would hand a
  zero-leaf spend full trust ([circuits.md](circuits.md#soundness-invariants)).
- `kemChunkHashes.length == K` (`WrongKemChunkHashCount`), stored under `batchId =
  startLeafIndex` (unique forever in an append-only tree); `applyOp` with `subtreeRoot =
  pub[3]`; emits `DisbursedPriv` (everything consensus-relevant is final in this transaction)
  and `DisbursePrivDisclosure(startLeafIndex, disclosure)`.
- **`submitDisburseKemChunk` is permissionless chunk delivery** — anyone holding the bytes can
  complete a batch. Checks in order: `UnknownBatch`, `BadChunkIndex`, `ChunkAlreadyAccepted`,
  exact byte length (`chunkArityOf(chunkIndex) × 1088`, `WrongKemCiphertextLength`), and
  `keccak256(chunkData)` against the batch-time commitment (`ChunkHashMismatch`) — so a late
  chunk is verifiably THE bytes the sender chose. On pass it emits
  `DisburseKemChunkAccepted(batchId, chunkIndex)`; the chunk DATA stays calldata-only (no
  re-emit). Chunk bookkeeping is discovery-transport state, not consensus state; a missing chunk
  leaves its outputs hash-committed but undiscoverable-by-scan — funds intact and spendable.

### `initializeConsumerOnly`

The consumer-only profile initializer: poseidon, token and batch size, nothing else — **no
arbiter epoch is ever minted, no KEM pk hash stored, no enterprise verifier wired**. It shares
the `initializer` version slot with `initialize` (a pool is one profile forever). On such a pool
every enterprise entrypoint reverts (the arbiter-key injection has no epoch to read) and the
registered modules are the whole op surface. "No key exists" was chosen over a burned
placeholder key. Pinned by `chains/evm/test/ConsumerOnly.t.sol`; deploy profile:
[deployment.md](deployment.md#deploy-profiles-and-the-consumer-module-family).

## One initializer

`initialize` is the enterprise profile's one-call initializer (`initializeConsumerOnly` above is
its consumer-only sibling on the same version slot), and it brings the pool up in its complete
production shape: Poseidon and the token, **all six verifiers**, the IMT parameters, the reentrancy latch, the
owner, and arbiter epoch 0 carrying both halves of the hybrid authority key. A deployed pool has
every entry point it will ever serve already backed by a real verifier, so no operation is ever
reachable-but-unbacked and a deploy is one transaction with no sequencing to get wrong.

Two rules make that shape enforceable rather than merely intended:

| rule | why |
|---|---|
| every verifier argument must be non-zero (`ZeroVerifier`) | a zeroed verifier turns its entry point into a call into `address(0)`: live, always reverting, unfixable short of an upgrade |
| the arbiter key must be non-zero and the KEM pk hash must be non-zero | `(0,0)` is the key foot-gun (§5.3 Q9); a zero hash is reserved to mean "this epoch was never minted", so minting one would make epoch 0 indistinguishable from an unallocated index |

The `initializer` modifier leaves the ERC-7201 version slot at **1**. Upgrades ship as
`upgradeToAndCall` carrying their own `reinitializer(n)` payload, written at that time against
the state each actually needs to move — versions **2** (the PQ envelope upgrade,
`reinitializeV2`) and **3** (the module layer, `reinitializeV3`,
[above](#the-op-module-layer)) are consumed; nothing is reserved in advance.

## Proxy and wiring

The pool is deployed behind a **UUPS (ERC-1967) proxy**. The implementation constructor only calls
`_disableInitializers()`, so a bare implementation can never be initialized or hijacked. All wiring
and tree parameters are set once in `initialize` through the proxy (see [One
initializer](#one-initializer) above). No `immutable` or constructor state carries consensus
meaning.

```
        deploy/addresses.<chainid>.json
                  |
   pool  ────────────────>  ERC1967Proxy (canonical, upgrade-stable address)
                                 |  delegatecall
   poolImpl ─────────────>  BongtuPool implementation
                                 |
        +──────────+──────────+──────────+──────────+─────────────+──────────────+
        v          v          v          v          v             v              v
    poseidon  depositVerif withdrawV  disburseV  transferV  transfer10V  transfer10x2V  + token
```

- **Poseidon** is a deployed contract, not a library: the circomlibjs creation bytecode
  (`chains/evm/test/fixtures/poseidon2.hex`) placed by inline `create`, giving the exact circomlib
  constants the circuits and `@bongtu/core` use. `chains/evm/test/Poseidon.t.sol` pins its output.
- **Verifiers** are the snarkjs solidity exports, renamed only (`Groth16Verifier` →
  `TransferVerifier`, …). `chains/evm/test/VerifierDrift.t.sol` gates that copy: it re-applies the
  one permitted substitution to each `circuits/verifiers/*.sol` and requires byte identity, so a
  regenerated circuit with a stale shipped verifier cannot pass `forge test`. They are fixed per implementation; a circuit change ships as
  `upgradeToAndCall`, which preserves the pool address and the entire tree/nullifier state.
- An `nPublic`-changing circuit edit is breaking: new verifier, new `IVerifiers` arity, new impl. It
  must ship as ONE atomic `upgradeToAndCall` carrying the implementation and the regenerated
  verifiers together — old proofs and new verifiers disagree on public count, so a two-step
  migration would leave a window in which every affected op reverts.
- New state goes at the **tail**, taking words off `uint256[47] __gap`, never inserted beside a
  logically-related slot: an insert re-strides every slot below it and would silently move the IMT
  root, the nullifier set and the arbiter epochs. `chains/evm/test/Upgrade.t.sol` pins state
  preservation across a swap, owner-only upgrade, and the initializer running exactly once.

The proxy owner is a single key on testnet. See [deployment.md](deployment.md) for the live
addresses and the arbiter-key-at-deploy coupling.
