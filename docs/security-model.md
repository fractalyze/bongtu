# Security model

What each party can see, what the chain guarantees about disclosure, and what is deliberately not
guaranteed. Mechanisms live in [protocol.md](protocol.md), [circuits.md](circuits.md) and
[contracts.md](contracts.md); this page states the boundaries.

Naming: **arbiter**, **auditor**, and the circuit/contract identifiers `authority*` /
`AUTHORITY_KEY` / `ARBITER_KEY_X/Y` all denote the SAME party — the holder of the key material every
envelope is encrypted to. Docs prose says "arbiter"; "auditor" names its compliance role;
`authority` is the upstream Zeto vocabulary the code inherits. Since the 2026-07-27 hybrid upgrade
that material is a **pair**: the bjj private key plus an ML-KEM-768 decapsulation key
(`AUTHORITY_KEM_KEY`). Opening a post-upgrade envelope needs both.

## Who sees what

| party | holds | can read |
|---|---|---|
| **arbiter (auditor)** | the arbiter bjj **private** key **and** the ML-KEM-768 decapsulation key | every note created and destroyed by every op: input owner, per-note value, salt, output owners — decrypted from on-chain envelopes alone, with no user key and no nullifier linkage |
| **employer (discloser)** | an ordinary sender key (disburse is permissionless since 2026-07-28); **no** arbiter key | the batch it authored (its own recipients and amounts) and its own notes. Nothing about other users' transfers |
| **public user (wallet)** | own bjj spending key | own notes only — via signature-gated `/notes`, or by trial-decrypting receiver ciphertext with its own key |
| **prover service (GPU box)** | no key of its own | everything in a `POST /prove` disburse request, in plaintext: the employer's bjj **spending scalar** (`inputOwnerPrivateKey`), the input note, and the full recipient/amount list. Institution-internal by necessity — a compromised prover box impersonates the employer |
| **chain observer** | nothing | commitments, nullifiers, roots, all ciphertext, transaction senders, and the **public** amounts: deposit `pub[0]` with the depositor address, withdraw `pub[0]` with the recipient address |

Hidden from the chain observer: transfer amounts, transfer parties, disburse total, disburse
recipients and their amounts, and the mapping from any nullifier to the leaf it spent.

The prover service's `/prove` sits behind two composed gates
([prover/README.md](../prover/README.md)): the Origin allowlist (`PROVER_ALLOWED_ORIGINS`) stops
browser drive-bys, and the shared-credential HTTP Basic auth (`PROVER_AUTH_SHA256` — the payroll
console's service login) is the real gate: it holds against any client, browser or not. One shared
operator credential is the single-employer PoC posture; production would use per-user SSO/OIDC.

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
   (owner, value, salt) under a key derived from `authorityPublicKey`. The envelope is not optional —
   it is wired into the constraint system, so a proof without a well-formed envelope does not exist.
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
tamper is *provable and immediately visible*. That is the honest strength of the guarantee —
detection, not prevention. Attribution is per-EOA: since the caller allowlist was retired
(2026-07-28, disburse is permissionless like every spend), a junk publish traces to the submitting
address, not to a pre-vetted employer identity. What openness does NOT cost is privacy — the batch
payload is ciphertext either way, readable only by each recipient and the arbiter.

## Post-quantum: the hybrid authority-envelope key

Everything bongtu encrypts is published on-chain and stays there. The pre-upgrade envelope key was
`ECDH(ephemeralPrivateKey, arbiterPublicKey)` on BabyJubJub, and **both** points are public — the
ephemeral key is a public signal copied into every op event, the arbiter key is in `arbiterEpochs`.
A future ECDLP break therefore retro-decrypts every authority envelope from chain data alone. Since
the envelope carries the op-wide plaintext including every recipient pubkey, it is also the key that
unlocks the receiver ciphertexts. That is the harvest-now-decrypt-later exposure the hybrid upgrade
closes.

Since **arbiter epoch 1** (live on GIWA 2026-07-27) the authority envelope key is a hybrid fold of
the classical ECDH secret and an ML-KEM-768 shared secret, and the shared secret is bound into the
proof:

```
kemSs[0..1]  = the 32-byte ML-KEM-768 shared secret as two LE 128-bit limbs   (private witness)
hybridKey[i] = Poseidon(5)([TAG_Ki, ecdh.x, ecdh.y, kemSs[0], kemSs[1]])      (envelope key)
kemBinding   = Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]])                    (public signal)
```

Every op additionally carries the 1088-byte `kemCiphertext` as calldata, length-checked on-chain
(`WrongKemCiphertextLength`) and re-emitted in the event so the arbiter never has to read calldata.
An adversary who breaks ECDLP alone recovers one of four Poseidon preimage components and nothing
else; an adversary who breaks ML-KEM alone still faces the intact ECDH half.

**The enforcement is asymmetric, and deliberately so.** The ECDH half keeps proof-fails-on-wrong-key:
the contract injects the stored arbiter key before `verifyProof`, so an envelope encrypted to the
wrong bjj key has no valid proof. The KEM half cannot get that guarantee — verifying an
encapsulation on-chain would mean ML-KEM inside the circuit (order 5–10M constraints per op), so the
chain checks the ciphertext's *length*, not its content. A junk-wrapped ciphertext therefore
downgrades to alarm-enforcement: the arbiter decapsulates, recomputes `Poseidon(3)([TAG_BIND, …])`,
finds it differs from the proof's `kemBinding`, and raises a first-class `envelope` alarm while
withholding the envelope. That is the same detection-and-attribution outcome class as a
length-padded junk disburse publish. Note what the attacker buys: the envelope is then unopenable by
anyone, including themselves — an immediate, attributable alarm and nothing else. `kemBinding` is a
circuit **output** computed from the witness `kemSs`, so a prover cannot claim a binding
inconsistent with the secret it actually encrypted under; the only reachable attack is
consistent-but-junk, which alarms.

**False-tamper is the failure mode worth defending, and both ends do.** A client encapsulating to a
stale KEM key, or an arbiter decapsulating with the wrong one, would stamp an honest operation as
tampered. So neither end trusts its bundled copy: clients read `arbiterKemPkHash(currentEpoch())`
from the pool **before** drawing KEM material and refuse on mismatch — or on a pre-KEM pool, which
this build cannot produce proofs for — and the indexer refuses to boot at all unless the
encapsulation key embedded in its own `AUTHORITY_KEM_KEY` hashes to the on-chain value. Fail-closed
both ways: the bundled key is chain-vouched, never trusted-from-bundle.

Scope, stated honestly:

- **Epoch 0 envelopes are ECDH-only forever.** The upgrade seals what comes after it, not what was
  already published. Every bjj recipient pubkey inside a pre-upgrade envelope is burned at Q-day,
  and for those identities the receiver-ciphertext attack is not stranded either. Full stranding
  applies only to identities that never appeared in a pre-upgrade envelope. `arbiterKemPkHash(0) ==
  0` is the on-chain, audit-facing statement of exactly where that boundary sits.
- **Receiver ciphertexts are still ECDH-only.** Per-recipient KEM is deferred: it costs ~38k gas per
  recipient (≈ +9.7M on a 256-batch) and only helps an adversary who already holds candidate
  recipient pubkeys — which, post-upgrade, appear nowhere on-chain in the clear. The interim defence
  is operational: bongtu addresses are shared off-channel, never published.
- **The KEM alarm is arbiter-attested, not publicly recomputable.** The disclosure alarm can be
  re-derived by anyone from public data; confirming a `kemBinding` mismatch requires decapsulating
  under the arbiter's secret key, so a third party can neither verify a raised alarm nor detect a
  suppressed one. Publishing the mismatching secret would break the envelope. Accepted: the alarm's
  consumer is the institution that operates the arbiter.
- **Signatures are unchanged.** Groth16 and the bjj EdDSA read-auth are classically sound; forgery
  is a forge-later problem, migratable before Q-day. ML-DSA is not part of this work.

Downgrade is structurally unavailable rather than merely discouraged: the upgraded circuits have no
ECDH-only encryption path, and the pool rejects any `kemCiphertext` that is not exactly 1088 bytes.
"Opting out" degenerates into the consistent-but-junk case, i.e. an alarm.

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
every spending base. Regression gates: `circuits/gates/test_zero_leaf_unsat.sh` (witness unsatisfiable) and
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
  there is no grace window, so any proof built against the previous key fails. It rotates the bjj
  key and the KEM pk hash together, so a client that has cached the old KEM key is caught by the
  pre-encapsulation guard rather than producing a false-tamper op.
- **Receiver ciphertexts are not post-quantum.** Only the authority envelope carries the hybrid key;
  per-recipient KEM is deferred on cost grounds. See the post-quantum section above for why the
  residual exposure needs an adversary who already holds recipient pubkeys.
- **Two-time pad on duplicate output owners (disburse only).** All outputs of a disburse batch share
  one ephemeral key and one nonce, so two outputs to the same owner would leak `m1 − m2`. This is
  mitigated by assembly-time rejection (`assertDistinctOwnerPubkeys`), not by the constraint system.
  The transfer circuit closed this structurally (U-X3): receiver ciphertext `i` is encrypted under
  `encryptionNonce + i` in-circuit, so duplicate output owners — including transfer-to-self — are
  safe there and the assembly-time ban no longer applies to transfer.
- **Discovery liveness depends on the indexer.** All ciphertext is on-chain and OP Stack posts it to
  L1, so the data is available; but reading it means `eth_getLogs` against an archive node or the
  bongtu indexer. Funds safety never depends on the indexer — a user who keeps their notes can spend
  without it — but the wallet has no fallback balance path
  ([wallet.md](wallet.md#indexer-dependency)).
- **No pause, no blacklist, no fine-grained roles.** The only emergency lever is a UUPS upgrade, and
  the only privileged role is the `Ownable2Step` owner (upgrades + arbiter rotation); every
  spend path, disburse included, is permissionless.
- **Signature equals spending key.** A wallet user who signs the derivation struct anywhere else has
  handed over their spending key ([wallet.md](wallet.md#key-derivation)).
- **Prover distribution is undesigned.** disburse proving needs a 1.3 GB zkey and a private GPU
  build; "we prove" is the PoC's distribution model.

## Testnet caveats

- **Single-party trusted setup.** The Groth16 zkeys come from a `groth16 setup` against a public
  powers-of-tau file with no phase-2 ceremony. Whoever ran setup can forge proofs. A phase-2 MPC is
  a mainnet prerequisite, and it must come *after* circuit freeze — any circuit edit re-runs setup
  and redeploys the verifier.
- **Demo arbiter keys.** The live pool's stored arbiter bjj key and the epoch-1 ML-KEM-768
  encapsulation key are both development keys whose private halves exist on a developer machine.
  They are fixed at deploy and coupled to the committed proof fixtures
  ([deployment.md](deployment.md#the-arbiter-key-is-fixed-at-deploy-and-the-fixtures-are-bound-to-it)).
- **Mock token.** The escrowed kKRW is `MockERC20` with a permissionless `mint`. Any production
  token must be non-fee-on-transfer and non-rebasing, or the pool is insolvent by construction.
- **Single-key ownership.** The proxy owner, the upgrade authority and the arbiter-rotation
  authority are one testnet EOA. Mainnet calls for a multisig or timelock.
- **Testnet only.** GIWA mainnet is not launched; every address and measurement here is Sepolia.
