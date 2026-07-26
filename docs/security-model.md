# Security model

What each party can see, what the chain guarantees about disclosure, and what is deliberately not
guaranteed. Mechanisms live in [protocol.md](protocol.md), [circuits.md](circuits.md) and
[contracts.md](contracts.md); this page states the boundaries.

Naming: **arbiter**, **auditor**, and the circuit/contract identifiers `authority*` /
`AUTHORITY_KEY` / `ARBITER_KEY_X/Y` all denote the SAME party — the holder of the one bjj private
key every envelope is encrypted to. Docs prose says "arbiter"; "auditor" names its compliance role;
`authority` is the upstream Zeto vocabulary the code inherits.

## Who sees what

| party | holds | can read |
|---|---|---|
| **arbiter (auditor)** | the arbiter bjj **private** key | every note created and destroyed by every op: input owner, per-note value, salt, output owners — decrypted from on-chain envelopes alone, with no user key and no nullifier linkage |
| **employer (discloser)** | a disburse-allowlisted sender key; **no** arbiter key | the batch it authored (its own recipients and amounts) and its own notes. Nothing about other users' transfers |
| **public user (wallet)** | own bjj spending key | own notes only — via signature-gated `/notes`, or by trial-decrypting receiver ciphertext with its own key |
| **prover service (GPU box)** | no key of its own | everything in a `POST /prove` disburse request, in plaintext: the employer's bjj **spending scalar** (`inputOwnerPrivateKey`), the input note, and the full recipient/amount list. Institution-internal by necessity — a compromised prover box impersonates the employer |
| **chain observer** | nothing | commitments, nullifiers, roots, all ciphertext, transaction senders, and the **public** amounts: deposit `pub[0]` with the depositor address, withdraw `pub[0]` with the recipient address |

Hidden from the chain observer: transfer amounts, transfer parties, disburse total, disburse
recipients and their amounts, and the mapping from any nullifier to the leaf it spent.

An arbiter-mode **indexer** is a fourth thing: it holds the arbiter private key and therefore every
owner's decrypted notes. Signature-gated `/notes` governs who may query it; it does not reduce what
that instance can see. Treat it as institution-internal infrastructure
([indexer.md](indexer.md#trust-boundary-arbiter-mode)).

```
   ┌── on-chain (public) ──────────────────────────────────────────────┐
   │  commitments · nullifiers · roots · ciphertext · deposit/withdraw │
   │  amounts + addresses                                              │
   └───────────────────────────────────────────────────────────────────┘
            │ arbiter private key            │ own spending key
            v                                v
   every note of every user            only this user's notes
   (values, salts, owners)             (trial-decrypt or signed /notes)
```

Batch size is fixed: a disburse always emits exactly `B = 256` output commitments and exactly 2054
ciphertext elements, with zero-value pad notes addressed to distinct dummy keys. The number of real
recipients is therefore not observable from calldata size or leaf count.

## Enforced auditor disclosure

The invariant: **every note creation and destruction is auditor-openable from on-chain data alone.**

It holds by construction, at three levels.

1. **In-circuit.** All four circuits encrypt an authority envelope over the op's inputs and outputs
   (owner, value, salt) to `authorityPublicKey`. The envelope is not optional — it is wired into the
   constraint system, so a proof without a well-formed envelope does not exist.
2. **Key injection.** The contract overwrites `authorityPublicKey` in the public-signal vector with
   the key stored in `arbiterEpochs` before every `verifyProof`. A sender cannot encrypt to its own
   key: the proof simply fails. Each event carries the epoch index, so the auditor picks the right
   key even at a rotation-boundary block.
3. **Publication.** deposit, transfer and withdraw carry their envelopes inside the verified public
   signals, which the contract copies verbatim into the event. disburse cannot — 2054 elements would
   dominate the verifier's public-input cost — so it publishes them as calldata and the contract
   enforces `receiverCiphertexts.length == disburseCiphertextLen`. There is no ciphertext-free
   disburse entry point.

**Where the chain stops.** For disburse the chain enforces *length*, not *content*: re-hashing 2054
field elements on-chain is not affordable. Content is bound by `disclosureHash`, a public signal of
the proof, and checked off-chain by the indexer, which recomputes the same Poseidon fold and raises
a first-class alarm on `mismatch`, `unverifiable` or `withheld`. So a malicious discloser can publish
length-correct junk: the transaction succeeds, the recipients' notes are undiscoverable, and the
tamper is *provable and immediately visible*. Combined with disburse being caller-gated to a known
allowlisted employer, that is the honest strength of the guarantee — detection and attribution, not
prevention.

## Why the zero-commitment guard exists

Upstream Zeto's `CheckHashes` has a zero-commitment escape: at `commitment == 0` the value, salt and
owner go unbound. That is sound in stock Zeto only because its value-keyed sparse Merkle tree makes
a zero commitment structurally impossible as a member. bongtu's index-keyed IMT commits `zeros[0] =
0` at every position ahead of the frontier and at every disburse pad slot, so **0 is a genuine,
membership-provable leaf** — and `leafIndices` is a prover-controlled input. Without the guard an
attacker spends a padded zero leaf at `enabled = 1` declaring an arbitrary value `X`: `CheckHashes`
escapes, `CheckNullifiers` binds a fresh nullifier, membership holds, the value belt is vacuous at
`enabled = 1`, and `CheckSum` mints `X` from nothing — a repeatable, permissionless drain through
`withdraw` or `transfer`, and through `disburse` for a compromised discloser.
`enabled[i] * IsZero(inputCommitments[i]) === 0` restores the SMT's implicit invariant explicitly on
every spending base. Regression gates: `circuits/test_zero_leaf_unsat.sh` (witness unsatisfiable) and
the contract enforcement tests. See [circuits.md](circuits.md#soundness-invariants).

## Residual gaps

Present-tense, deliberate, and not fixed by anything in the tree today.

- **Funding-path privacy is weak.** disburse hides the total and the split, but deposit is fully
  public (amount plus depositor address). In a fresh institutional pool the employer is the only
  large-note source, so the disburse input note is de-facto linkable to a specific deposit —
  fact-of-funding and magnitude leak even though the split does not. Input-note unlinkability is
  bounded by the number of independent depositors. Mitigations are operational: pre-fund well ahead,
  split deposits. This grows with adoption; it is not a property of the cryptography.
- **Arbiter rotation invalidates in-flight proofs.** `rotateArbiter` takes effect immediately and
  there is no grace window, so any proof built against the previous key fails.
- **Two-time pad on duplicate output owners.** All outputs of a transfer or batch share one ephemeral
  key and one nonce, so two outputs to the same owner would leak `m1 − m2`. This is mitigated by
  assembly-time rejection (`assertDistinctOwnerPubkeys`), not by the constraint system. A
  per-output-nonce construction would make it structural.
- **Discovery liveness depends on the indexer.** All ciphertext is on-chain and OP Stack posts it to
  L1, so the data is available; but reading it means `eth_getLogs` against an archive node or the
  bongtu indexer. Funds safety never depends on the indexer — a user who keeps their notes can spend
  without it — but the wallet has no fallback balance path
  ([wallet.md](wallet.md#indexer-dependency)).
- **No pause, no blacklist, no fine-grained roles.** The only emergency lever is a UUPS upgrade, and
  the only role split is `Ownable2Step` plus the disburse allowlist.
- **Signature equals spending key.** A wallet user who signs the derivation struct anywhere else has
  handed over their spending key ([wallet.md](wallet.md#key-derivation)).
- **Prover distribution is undesigned.** disburse proving needs a 1.3 GB zkey and a private GPU
  build; "we prove" is the PoC's distribution model.

## Testnet caveats

- **Single-party trusted setup.** The Groth16 zkeys come from a `groth16 setup` against a public
  powers-of-tau file with no phase-2 ceremony. Whoever ran setup can forge proofs. A phase-2 MPC is
  a mainnet prerequisite, and it must come *after* circuit freeze — any circuit edit re-runs setup
  and redeploys the verifier.
- **Demo arbiter key.** The live pool's stored arbiter key is a development key whose private half
  exists on a developer machine. It is fixed at deploy and coupled to the committed proof fixtures
  ([deployment.md](deployment.md#the-arbiter-key-is-fixed-at-deploy-and-the-fixtures-are-bound-to-it)).
- **Mock token.** The escrowed kKRW is `MockERC20` with a permissionless `mint`. Any production
  token must be non-fee-on-transfer and non-rebasing, or the pool is insolvent by construction.
- **Single-key ownership.** The proxy owner, the upgrade authority, the arbiter-rotation authority
  and the disburse allowlist admin are one testnet EOA. Mainnet calls for a multisig or timelock.
- **Testnet only.** GIWA mainnet is not launched; every address and measurement here is Sepolia.
