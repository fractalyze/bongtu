# Circuits

Six circom circuits over four bases, one shared membership gadget, one shared envelope
construction — the **enterprise** family; the **consumer** (no-auditor) family adds six more
tops over four sibling bases ([below](#consumer-circuits-and-public-surfaces)). Sources:
`circuits/*.circom` (top-levels) and `circuits/lib/*.circom` (vendored bases). Provenance
against upstream Zeto is in [zeto-derivation.md](zeto-derivation.md); build commands are in
[toolchain.md](toolchain.md).

| circuit | template | arity | constraints | publics | domain |
|---|---|---|---|---|---|
| `deposit.circom` | `BongtuDepositAuthority(2)` | 0-in / 2-out | 14,127 | 19 | 2^14 |
| `transfer.circom` | `ZetoTransferSmall(2,2,32)` | 2-in / 2-out | 64,394 | 37 | 2^16 |
| `transfer10.circom` | `ZetoTransferSmall(10,10,32)` | 10-in / 10-out | 261,683 | 141 | 2^18 |
| `transfer10x2.circom` | `ZetoTransferSmall(10,2,32)` | 10-in / 2-out | 212,386 | 68 | 2^18 |
| `withdraw.circom` | `BongtuWithdraw(2,1,32)` (wraps `CheckNullifiersInputsOutputsValueIMT`, adds public `recipient`) | 2-in / 1-out | 54,320 | 27 | 2^16 |
| `disburse.circom` | `Zeto(1,16,32)` | 1-in / 16-out | 208,719 | 11 | 2^18 |
| `disburse256.circom` | `Zeto(1,256,32)` | 1-in / 256-out | 2,796,719 | 11 | 2^22 |

Constraint counts measured 2026-07-28 (`snarkjs r1cs info` over `circuits/out/*.r1cs`).
`disburse.circom` is the dev-loop instantiation of the *same* base as `disburse256.circom`;
`transfer10.circom` and `transfer10x2.circom` are `transfer.circom`'s base at other arities. The
live pool carries the 256 verifier. Note that the dev-loop disburse is not optional collateral: a
public count is a per-base property, so an envelope change regenerates **seven** verifier/zkey pairs.

**transfer10x2 exists because outputs, not inputs, are what a spend pays for on chain.** Each
output is a depth-32 IMT leaf append (~0.93M gas), and on a real spend eight of transfer10's ten
outputs are zero-value padding — `transfer10` measured 11,592,399 gas, ~9.3M of it those appends.
Dropping to two outputs (payment + change, or merged note + zero change) keeps the ten-note
consolidation and sheds the padding. The input side — ten membership proofs — is unchanged, which
is also why the constraint saving is only ~19%.

**transfer10 has almost no headroom.** snarkjs picks `domainSize = 2^(floor(log2(nConstraints +
nPublic)) + 1)`, so transfer10 stays at 2^18 only while `nConstraints <= 262,002` — **319
constraints of margin**. Anything added to `ZetoTransferSmall` (an extra hash, one more range
check) spills it to 2^19, which doubles the zkey and the proving time. Measure before and after any
base change. transfer10x2 shares the 2^18 domain with 49,689 constraints of margin — cutting eight
outputs does not reach 2^17, because 2^17 caps at ~131k and the ten membership proofs alone exceed
that.

## The hybrid envelope key

All four bases derive their `SymmetricEncrypt` key by folding the classical ECDH secret together
with an ML-KEM-768 shared secret supplied as a private witness, and expose a public commitment to
that secret:

```circom
kemSsRange[i] = Num2Bits(128);  kemSsRange[i].in <== kemSs[i];   // canonical-limb hygiene
hybridKey[0] <== Poseidon(5)([TAG_K0,   ecdh[0], ecdh[1], kemSs[0], kemSs[1]]);
hybridKey[1] <== Poseidon(5)([TAG_K1,   ecdh[0], ecdh[1], kemSs[0], kemSs[1]]);
kemBinding   <== Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]]);
```

`kemBinding` is declared as the **last** circuit output, which is why every existing output index is
unchanged and every public-*input* index shifted by exactly one. Because it is computed from the
witness, a prover cannot claim a binding inconsistent with the secret it encrypted under; the
mechanism and its alarm-enforced trade-off are in
[security-model.md](security-model.md#post-quantum-the-hybrid-authority-envelope-key), the exact
derivation in [protocol.md](protocol.md#the-hybrid-envelope-key). There is no ECDH-only encryption
path left in any base. Receiver-side `EncryptOutputs` is untouched.

## Public surfaces

circom orders public signals as circuit **outputs first** (declaration order), then the top-level
`public` inputs (declaration order). The contract indexes into these vectors literally, so any
reordering is a breaking change requiring a new verifier and a pool upgrade.

**deposit — `uint[19]`**

| idx | signal |
|---|---|
| 0 | `out` (sum of output values; the amount pulled from the depositor) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..12 | `cipherTextAuthority[10]` |
| 13 | `kemBinding` |
| 14..15 | `outputCommitments[2]` |
| 16 | `encryptionNonce` |
| 17..18 | `authorityPublicKey[2]` |

**transfer — `uint[37]`**

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` (receiver-decryptable, one per output) |
| 10..25 | `cipherTextAuthority[16]` |
| 26 | `kemBinding` |
| 27..28 | `nullifiers[2]` |
| 29 | `root` |
| 30..31 | `enabled[2]` |
| 32..33 | `outputCommitments[2]` |
| 34 | `encryptionNonce` |
| 35..36 | `authorityPublicKey[2]` |

**transfer10 — `uint[141]`**

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..41 | `cipherTexts[10][4]` (receiver-decryptable, one per output) |
| 42..105 | `cipherTextAuthority[64]` |
| 106 | `kemBinding` |
| 107..116 | `nullifiers[10]` |
| 117 | `root` |
| 118..127 | `enabled[10]` |
| 128..137 | `outputCommitments[10]` |
| 138 | `encryptionNonce` |
| 139..140 | `authorityPublicKey[2]` |

Same base as transfer, so the *declaration* order is identical and only the run lengths change —
but every index past 1 moves, so transfer10 needs its own verifier and its own contract indexing.

**transfer10x2 — `uint[68]`**

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` (receiver-decryptable, one per output) |
| 10..40 | `cipherTextAuthority[31]` |
| 41 | `kemBinding` |
| 42..51 | `nullifiers[10]` |
| 52 | `root` |
| 53..62 | `enabled[10]` |
| 63..64 | `outputCommitments[2]` |
| 65 | `encryptionNonce` |
| 66..67 | `authorityPublicKey[2]` |

The authority run is 31 rather than a multiple of 3 plus one by accident: the plaintext is
`2 + 2*10 + 4*2 = 30`, already a multiple of 3, so the sponge adds no padding and only the final
squeeze.

**withdraw — `uint[27]`**

| idx | signal |
|---|---|
| 0 | `out` (= `sum(inputs) − sum(outputs)`, the ERC-20 amount pushed) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..15 | `cipherTextAuthority[13]` |
| 16 | `kemBinding` |
| 17..18 | `nullifiers[2]` |
| 19 | `root` |
| 20..21 | `enabled[2]` |
| 22 | `outputCommitments[0]` (the change note) |
| 23 | `encryptionNonce` |
| 24..25 | `authorityPublicKey[2]` |
| 26 | `recipient` (L1 payout address as a field element; the contract range-checks uint160 and pays it instead of msg.sender — the relayable stealth exit) |

**disburse / disburse256 — `uint[11]`**

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2 | `disclosureHash` |
| 3 | `subtreeRoot` |
| 4 | `kemBinding` |
| 5 | `nullifiers[0]` |
| 6 | `root` |
| 7 | `enabled[0]` |
| 8 | `encryptionNonce` |
| 9..10 | `authorityPublicKey[2]` |

Neither the batch's ciphertext nor the 1088-byte `kemCiphertext` rides in the public vector. The
former travels as a separate calldata argument bound by `disclosureHash`; the latter as a `bytes`
argument bound by `kemBinding` (see [protocol.md](protocol.md) and [contracts.md](contracts.md)).

## Consumer circuits and public surfaces

The consumer (no-auditor) family: six tops over four sibling bases, each base derived from a
vendored enterprise base above with the parent untouched — per-file provenance and deltas in
[zeto-derivation.md](zeto-derivation.md#the-consumer-no-auditor-family), design record in
`.dev/op-module-design.md` (OPMOD §2/§3). These circuits are verified by op **modules**, not
the pool ([contracts.md](contracts.md#the-op-module-layer)); the module indexes the vector
literally, so a reorder is a breaking change requiring a new verifier and a module swap.

| circuit | template | arity | constraints | publics | domain |
|---|---|---|---|---|---|
| `depositPriv.circom` | `BongtuConsumerDeposit(2)` | 0-in / 2-out | 20,509 | 16 | 2^15 |
| `transferPriv.circom` | `BongtuConsumerTransfer(2,2,32)` | 2-in / 2-out | 60,704 | 20 | 2^16 |
| `transfer10x2Priv.circom` | `BongtuConsumerTransfer(10,2,32)` | 10-in / 2-out | 204,984 | 36 | 2^18 |
| `withdrawPriv.circom` | `BongtuWithdrawPriv(2,1,32)` | 2-in / 1-out | 52,614 | 16 | 2^16 |
| `disbursePriv.circom` | `BongtuConsumerDisburse(1,16,32)` | 1-in / 16-out | 214,769 | 8 | 2^18 |
| `disbursePriv256.circom` | `BongtuConsumerDisburse(1,256,32)` | 1-in / 256-out | 3,049,889 | 8 | 2^22 |

Constraint counts measured 2026-09-03. `transferPriv` lands at 2^16 with ~4.8k of margin,
resolving the spec's TIGHT flag; `disbursePriv` is the dev-loop instantiation of the same base
as `disbursePriv256` (the enterprise disburse/disburse256 pattern — an envelope change on this
base regenerates both pairs). The deprecated `transfer10` has no consumer twin.

Versus its enterprise twin, every consumer top **drops** `cipherTextAuthority[·]`, `kemBinding`
and `authorityPublicKey[2]` — there is no authority material anywhere in the family — and
**adds** `viewTags[nOut]` as the last output run; `depositPriv` and `withdrawPriv` additionally
gain receiver ciphertexts their twins never had (the enterprise deposit publishes only an
authority envelope; the enterprise withdraw's change note is arbiter-recoverable). Receiver
encryption is the hybrid per-output construction (ECDH against the recipient's note-layer VIEW
key folded with a per-output ML-KEM-768 secret, nonce `encryptionNonce + i`, uniform across all
six shapes). Every input-side soundness constraint of the section below survives each base edit
verbatim; the per-circuit preservation table is OPMOD §2.1.

**depositPriv — `uint[16]`** (enterprise deposit: `uint[19]`)

| idx | signal |
|---|---|
| 0 | `out` (sum of output values; the amount the module pulls) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..10 | `cipherTexts[2][4]` (receiver-decryptable, one per output) |
| 11..12 | `viewTags[2]` |
| 13..14 | `outputCommitments[2]` |
| 15 | `encryptionNonce` |

**transferPriv — `uint[20]`** (enterprise transfer: `uint[37]`)

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` |
| 10..11 | `viewTags[2]` |
| 12..13 | `nullifiers[2]` |
| 14 | `root` |
| 15..16 | `enabled[2]` (module-injected: `nullifier[i] != 0`) |
| 17..18 | `outputCommitments[2]` |
| 19 | `encryptionNonce` |

**transfer10x2Priv — `uint[36]`** (enterprise transfer10x2: `uint[68]`)

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` |
| 10..11 | `viewTags[2]` |
| 12..21 | `nullifiers[10]` |
| 22 | `root` |
| 23..32 | `enabled[10]` (module-injected) |
| 33..34 | `outputCommitments[2]` |
| 35 | `encryptionNonce` |

**withdrawPriv — `uint[16]`** (enterprise withdraw: `uint[27]`)

| idx | signal |
|---|---|
| 0 | `out` (= `sum(inputs) − change`, the ERC-20 amount the module pushes) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..6 | `cipherTexts[1][4]` (the change note) |
| 7 | `viewTags[1]` |
| 8..9 | `nullifiers[2]` |
| 10 | `root` |
| 11..12 | `enabled[2]` (module-injected) |
| 13 | `outputCommitments[0]` (the change note) |
| 14 | `encryptionNonce` |
| 15 | `recipient` (L1 payout address; the module range-checks uint160 and pays it, never msg.sender — relayable like the enterprise withdraw) |

**disbursePriv / disbursePriv256 — `uint[8]`** (enterprise disburse: `uint[11]`)

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2 | `disclosureHash` (the EXTENDED fold over `receiverCts[4B] ++ viewTags[B] ++ outputCommitments[B]`) |
| 3 | `subtreeRoot` |
| 4 | `nullifiers[0]` |
| 5 | `root` |
| 6 | `enabled[0]` (module-injected constant 1 after a `ZeroNullifier` check) |
| 7 | `encryptionNonce` |

The batch's 6·B-element `disclosure` array and every circuit's per-recipient 1088-byte KEM
ciphertexts ride module calldata, not the public vector; the on-chain checks they get are the
module's ([contracts.md](contracts.md#the-op-module-layer)).

## Soundness invariants

Three constraints guard the input side. They are not implied by one another, nor by the contract's
`enabled` injection.

```circom
enabled[i] * (enabled[i] - 1) === 0;                 // enabled is boolean
(1 - enabled[i]) * inputValues[i] === 0;             // value belt
enabled[i] * IsZero(inputCommitments[i]) === 0;      // zero-commitment guard
```

They are not all present in all bases:

| base | boolean + value belt | zero-commitment guard |
|---|---|---|
| `lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom` (transfer, transfer10, transfer10x2) | lines 103–104 | line 117 |
| `lib/check-nullifiers-value-imt-base.circom` (withdraw) | lines 109–110 | line 123 |
| `lib/anon_enc_nullifier_non_repudiation_imt_base.circom` (disburse, disburse256) | absent | line 129 |

The disburse omission is sound rather than an oversight: `disburseWithCiphertexts` reverts
`ZeroNullifier` on a zero nullifier and then injects `enabled[0] = 1` unconditionally, so
`enabled[0] = 1` on every accepted call and the value belt is vacuous there. The guard is not — see
below.

**Value belt.** `CheckHashes` and `CheckNullifiers` both accept a zero commitment / zero nullifier
with *any* value, and `CheckSum` adds `inputValues[i]` unconditionally. A fabricated input
`{nullifier: 0, commitment: 0, value: X, enabled: 0}` would otherwise satisfy every other
constraint and inflate the output sum. Binding value to `enabled` — which the contract derives as
`nullifier != 0` — makes that witness unsatisfiable: `nullifier = 0 ⇒ enabled = 0 ⇒ value = 0`;
`nullifier ≠ 0 ⇒ enabled = 1 ⇒ real membership required.`

**Zero-commitment guard.** `enabled = 1` is not covered by the value belt. The index-keyed IMT
commits `zeros[0] = 0` at every position ahead of the frontier and at every disburse pad slot, so
`0` is a genuine, membership-provable leaf — the upstream `CheckHashes` zero-commitment escape
becomes a mint-from-nothing. Rationale in [security-model.md](security-model.md); the exploit trace
lives there, not here.

`disburse` carries the guard because its single input is always `enabled = 1`, so the guard is the
only thing standing between a compromised discloser and a mint from a zero leaf.

Two further invariants live outside the circuits and must be enforced by whoever assembles a
witness:

- **Distinct output owner pubkeys (disburse only).** All outputs of a disburse batch share one
  ephemeral key and one `encryptionNonce`, so two outputs to the same owner leak
  `c1 − c2 = m1 − m2`. `assertDistinctOwnerPubkeys` (`packages/core/src/notes/note.ts`) rejects
  duplicates before proving. The transfer arities are exempt since U-X3 (§11-8 v1.1): their
  base encrypts receiver ciphertext `i` under `encryptionNonce + i` in-circuit
  (`encrypt-outputs-per-output-nonce.circom`), so duplicate owners — a self-send, or a merge whose
  outputs all share one key — are structurally safe, and receivers decrypt
  `ct_i` with `nonce + i`. deposit is exempt too: both
  its outputs belong to the depositor and it publishes no per-recipient ciphertext, only a single
  authority envelope over both.
- **Non-zero output commitments.** Enforced on-chain (`ZeroOutputCommitment`), not in-circuit.

## Structure and `-l` resolution

Top-levels are thin: each is a `component main { public [...] } = <Template>(...)` over a base in
`circuits/lib/`.

```
circuits/                                          include spelling        resolving -l root
  disburse256.circom  ──> ..._imt_base.circom       bare                    lib
  disburse.circom     ──> (same base, nOutputs=16)  bare                    lib
  transfer.circom     ──> ..._imt_small_base.circom bare                    lib
  transfer10.circom   ──> (same base, 10-in/10-out)  bare                   lib
  transfer10x2.circom ──> (same base, 10-in/2-out)   bare                   lib
  withdraw.circom     ──> check-nullifiers-value-imt-base.circom  bare      lib
  deposit.circom      ──> deposit_authority_imt_base.circom       bare      lib

  the three SPENDING bases (disburse / transfer / withdraw) each include:
    check-imt-proof.circom                            bare      lib   (vendored membership)
    lib/check-{positive,hashes,nullifiers}.circom               $ZETO
    lib/check-sum.circom          (transfer/disburse only)      $ZETO
    lib/{ecdh,encrypt}.circom     (withdraw)  /  lib/encrypt-outputs.circom (transfer/disburse)   $ZETO
    node_modules/circomlib/circuits/{babyjub,comparators}.circom            $ZETO

  the DEPOSIT base (0-in — no membership, no nullifiers) includes only:
    lib/{check-positive,check-hashes,ecdh,encrypt}.circom       $ZETO
    node_modules/circomlib/circuits/babyjub.circom              $ZETO
```

`build/prove_all.sh` passes three roots — `-l "$ZETO" -l "$CIRCOMLIB" -l lib`, with
`CIRCOMLIB` defaulting to `$ZETO/node_modules`. Only two do work:

| `-l` root | resolves |
|---|---|
| `$ZETO` | the `lib/`-prefixed upstream sub-checks **and** the `node_modules/`-prefixed circomlib includes |
| `lib` (repo-relative) | every bare-name include — the four vendored bongtu bases plus `check-imt-proof.circom`, i.e. all five files in `circuits/lib/` |
| `$ZETO/node_modules` | nothing — no include in the closure is spelled `circomlib/circuits/...` |

Self-containment on the membership and envelope path comes from the *spelling*, not the search
order (`lib` is passed last). The bare names have no counterpart at the `$ZETO` root — the
checkout does hold a git-**untracked** leftover at `$ZETO/lib/check-imt-proof.circom` (not
upstream), but its `lib/`-prefixed spelling never matches a bare include — so only `-l lib` can
supply them, and no untracked file in the Zeto checkout is load-bearing. The upstream sub-checks
stay resolved out of the pinned checkout, so they are byte-identical to upstream by construction.

How to build, prove and run the attack gates is owned by
[`circuits/README.md`](../circuits/README.md); exact invocations are in [toolchain.md](toolchain.md).
