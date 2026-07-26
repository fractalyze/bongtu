# Contracts

`contracts/src/BongtuPool.sol` is the whole consensus surface: one shielded pool holding the
single-frontier IMT, the nullifier set, ERC-20 custody, the arbiter epoch list, and four Groth16
verifier calls. Everything else in `contracts/src/` is a generated verifier, an interface, or a
proxy/ownership util. How to build and test the folder is owned by
[`contracts/README.md`](../contracts/README.md).

## Entry points

| function | publics | access | tree effect |
|---|---|---|---|
| `deposit(a,b,c,pub)` | `uint[18]` | permissionless | appends 2 leaves, pulls `pub[0]` tokens |
| `transfer(a,b,c,pub)` | `uint[36]` | permissionless | spends 2 nullifiers, appends 2 leaves |
| `withdraw(a,b,c,pub)` | `uint[25]` | permissionless | spends 2 nullifiers, appends 1 change leaf, pushes `pub[0]` tokens |
| `disburseWithCiphertexts(a,b,c,pub,receiverCiphertexts)` | `uint[10]` + `uint256[]` | owner or `disburseAllowed[msg.sender]` | spends 1 nullifier, attaches a `B`-leaf subtree |

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
| `enabled[i]` | `nullifier[i] != 0` (transfer, withdraw); constant `1` (disburse) | a prover that could set `enabled = 0` on a value-carrying input would skip membership — mint-from-nothing |
| `authorityPublicKey[2]` | `currentArbiterKey()` from storage | a sender that could name the key would encrypt the envelope to itself and silently kill non-repudiation |

A proof made against different values simply fails verification (`InvalidProof`). The circuit-side
belts that make this injection sufficient are in [circuits.md](circuits.md#soundness-invariants).

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

deposit, transfer and withdraw need no such argument: their authority envelopes ride inside the
public-signal vector, so the verifier itself binds them, and the contract copies those exact words
into the event.

## Output commitments

- **Zero output commitments are rejected** on all three appending paths (`ZeroOutputCommitment`).
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
| `Deposited` | epoch, first leaf index, both commitments, amount, `ecdhPublicKey`, `uint256[10]` authority envelope, nonce, root |
| `Transferred` | epoch, 2 nullifiers, 2 commitments, `ecdhPublicKey`, 2×`uint256[4]` receiver ciphertexts, `uint256[16]` authority envelope, nonce, root |
| `Withdrawn` | epoch, 2 nullifiers, amount, change commitment, `ecdhPublicKey`, `uint256[13]` authority envelope, nonce, root |
| `Disbursed` | epoch, nullifier, `subtreeRoot`, `disclosureHash`, `ecdhPublicKey`, nonce, root |
| `DisburseCiphertexts(startLeafIndex, receiverCiphertexts)` | the 2054-element array |
| `ArbiterRotated(epoch, keyX, keyY, activatedBlock)` | key rotation |

Every op event carries the **epoch index**, so an auditor picks the exact arbiter key even at a
rotation-boundary block. Without `ecdhPublicKey` + `encryptionNonce` no recipient can derive a
decryption key at all, which is why they are in the event rather than off-chain.

## Arbiter epochs

`arbiterEpochs` is an append-only array of `{keyX, keyY, activatedBlock}`. `initialize` seeds epoch
0 and **requires** a non-zero key (`ZeroArbiterKey`), killing the `(0,0)` foot-gun.
`rotateArbiter(newKey)` appends and emits. In-flight proofs built against the previous key become
invalid at rotation — there is no grace window.

## Proxy and wiring

The pool is deployed behind a **UUPS (ERC-1967) proxy**. The implementation constructor only calls
`_disableInitializers()`, so a bare implementation can never be initialized or hijacked. All wiring
and tree parameters are set once in `initialize` through the proxy: Poseidon, the four verifiers,
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
        +────────────+───────────+────────────+────────────+
        v            v           v            v            v
    poseidon    depositVerif  withdrawV   disburseV    transferV      + token
```

- **Poseidon** is a deployed contract, not a library: the circomlibjs creation bytecode
  (`contracts/test/fixtures/poseidon2.hex`) placed by inline `create`, giving the exact circomlib
  constants the circuits and `@bongtu/core` use. `contracts/test/Poseidon.t.sol` pins its output.
- **Verifiers** are the snarkjs solidity exports, renamed only (`Groth16Verifier` →
  `TransferVerifier`, …). They are fixed per implementation; a circuit change ships as
  `upgradeToAndCall`, which preserves the pool address and the entire tree/nullifier state.
- An `nPublic`-changing circuit edit is breaking: new verifier, new `IVerifiers` arity, new impl.
- `uint256[50] __gap` reserves trailing storage for a future implementation.
  `contracts/test/Upgrade.t.sol` pins state preservation, owner-only upgrade, re-init rejection and
  implementation locking.

The proxy owner is a single key on testnet. See [deployment.md](deployment.md) for the live
addresses and the arbiter-key-at-deploy coupling.
