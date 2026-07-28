# Contracts

`contracts/src/BongtuPool.sol` is the whole consensus surface: one shielded pool holding the
single-frontier IMT, the nullifier set, ERC-20 custody, the arbiter epoch list, and six Groth16
verifier calls. Everything else in `contracts/src/` is a generated verifier, an interface, or a
proxy/ownership util. How to build and test the folder is owned by
[`contracts/README.md`](../contracts/README.md).

## Entry points

| function | publics | access | tree effect |
|---|---|---|---|
| `deposit(a,b,c,pub,kemCiphertext)` | `uint[19]` | permissionless | appends 2 leaves, pulls `pub[0]` tokens |
| `transfer(a,b,c,pub,kemCiphertext)` | `uint[37]` | permissionless | spends 2 nullifiers, appends 2 leaves |
| `transfer10(a,b,c,pub,kemCiphertext)` | `uint[141]` | permissionless | spends 10 nullifiers, appends 10 leaves |
| `transfer10x2(a,b,c,pub,kemCiphertext)` | `uint[68]` | permissionless | spends 10 nullifiers, appends 2 leaves |
| `withdraw(a,b,c,pub,kemCiphertext)` | `uint[26]` | permissionless | spends 2 nullifiers, appends 1 change leaf, pushes `pub[0]` tokens |
| `disburseWithCiphertexts(a,b,c,pub,receiverCiphertexts,kemCiphertext)` | `uint[11]` + `uint256[]` | owner or `disburseAllowed[msg.sender]` | spends 1 nullifier, attaches a `B`-leaf subtree |

Every op takes the ML-KEM-768 `kemCiphertext` as a trailing `bytes calldata` argument and reverts
`WrongKemCiphertextLength` unless it is exactly `KEM_CIPHERTEXT_LEN == 1088` bytes. It is not
otherwise inspectable on-chain — its correctness is bound off-chain by the proof's `kemBinding`
public signal and the arbiter's decapsulation
([security-model.md](security-model.md#post-quantum-the-hybrid-authority-envelope-key)).

`rotateArbiter`, `setDisburseAllowed` and `_authorizeUpgrade` are `onlyOwner`. Every operation runs
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
  the write side too is defence in depth (`contracts/test/Enforcement.t.sol`).
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
0 and **requires** a non-zero key (`ZeroArbiterKey`), killing the `(0,0)` foot-gun. In-flight proofs
built against the previous key become invalid at rotation — there is no grace window.

The struct is **frozen**: appending a field would re-stride the dynamic array and corrupt live
epochs across an upgrade. So the per-epoch ML-KEM-768 encapsulation-key hash lives in a sibling
`mapping(uint256 => bytes32) public arbiterKemPkHash`, added in V2 out of the first slot of the
original `uint256[50] __gap` (now `uint256[47]`, after V4 and V5 each took another word).

`rotateArbiter(newKey, newKemPkHash)` writes both and emits both events. The bjj-only overload was
**removed**, not kept alongside: a rotation that skipped the hash would mint a zero-hash epoch
indistinguishable from the pre-KEM marker. `arbiterKemPkHash[epoch] == 0` means exactly one thing —
that epoch predates the hybrid envelope. The full 1184-byte key is distributed off-chain and
verified by clients against this hash ([deployment.md](deployment.md#the-hybrid-pq-upgrade-2026-07-27)).

`initializeV2` is the one-shot (`reinitializer(2)`) migration payload for `upgradeToAndCall`: it
swaps the four verifier addresses and mints the first hybrid epoch in the same transaction as the
implementation swap, because old proofs and new verifiers disagree on public count and no window may
exist between them.

`initializeV3` (`reinitializer(3)`) is the self-send migration payload (U-X3): a **verifier-only**
swap of `transferVerifier` and nothing else. The witness shape and the 37 publics are unchanged —
only the transfer verifying key moves — so no epoch is minted, since an epoch boundary tells the
indexer and the wallets that arbiter key material changed, and none did. `reinitializer(3)` only
requires version < 3, so the payload would also run on a pool that never took V2 and would then put
`initializeV2` permanently out of reach; the V2-then-V3 ordering is enforced by
`deploy/UpgradeSelfSend.s.sol`, whose pre-flight reads the initializer version from storage and
refuses anything below 2.

`initializeV4` (`reinitializer(4)`) is the transfer10 migration payload (U-Z1) and is **add-only**:
it sets `transfer10Verifier`, which was previously `address(0)` — so before it runs, `transfer10`
is simply unreachable — and touches nothing else. The 2-in `transfer` path keeps its own verifier
and keeps working across the upgrade, and no epoch is minted because no arbiter key material moves.
Ordering is pinned the same way as V3, by the deploy script's storage pre-flight.

`initializeV5` (`reinitializer(5)`) is the transfer10x2 migration payload (U-Z3), shaped exactly
like V4: add-only (`transfer10x2Verifier`, previously `address(0)`, so `transfer10x2` is
unreachable until it runs), no epoch, ordering pinned by the deploy script's storage pre-flight.

## Proxy and wiring

The pool is deployed behind a **UUPS (ERC-1967) proxy**. The implementation constructor only calls
`_disableInitializers()`, so a bare implementation can never be initialized or hijacked. All wiring
and tree parameters are set once in `initialize` through the proxy: Poseidon, the four v1 verifiers,
the token, `B`, `LOG_B`, `disburseCiphertextLen`, the zeros ladder, the frontier, the empty-tree
root, arbiter epoch 0, the reentrancy latch, and the owner. No `immutable` or constructor state
carries consensus meaning.

```
        deploy/addresses.91342.json
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
  (`contracts/test/fixtures/poseidon2.hex`) placed by inline `create`, giving the exact circomlib
  constants the circuits and `@bongtu/core` use. `contracts/test/Poseidon.t.sol` pins its output.
- **Verifiers** are the snarkjs solidity exports, renamed only (`Groth16Verifier` →
  `TransferVerifier`, …). `contracts/test/VerifierDrift.t.sol` gates that copy: it re-applies the
  one permitted substitution to each `circuits/verifiers/*.sol` and requires byte identity, so a
  regenerated circuit with a stale shipped verifier cannot pass `forge test`. They are fixed per implementation; a circuit change ships as
  `upgradeToAndCall`, which preserves the pool address and the entire tree/nullifier state.
- An `nPublic`-changing circuit edit is breaking: new verifier, new `IVerifiers` arity, new impl.
  The hybrid-envelope upgrade was exactly that — `kemBinding` took each vector to 19/37/26/11 — and
  it shipped as one atomic `upgradeToAndCall` carrying impl and verifiers together.
- `uint256[47] __gap` reserves trailing storage for a future implementation.
  `contracts/test/Upgrade.t.sol` pins state preservation, owner-only upgrade, re-init rejection and
  implementation locking.

The proxy owner is a single key on testnet. See [deployment.md](deployment.md) for the live
addresses and the arbiter-key-at-deploy coupling.
