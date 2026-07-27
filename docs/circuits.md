# Circuits

Four circom circuits, one shared membership gadget, one shared envelope construction. Sources:
`circuits/*.circom` (top-levels) and `circuits/lib/*.circom` (vendored bases). Provenance against
upstream Zeto is in [zeto-derivation.md](zeto-derivation.md); build commands are in
[toolchain.md](toolchain.md).

| circuit | template | arity | constraints | publics |
|---|---|---|---|---|
| `deposit.circom` | `BongtuDepositAuthority(2)` | 0-in / 2-out | 14,127 | 19 |
| `transfer.circom` | `ZetoTransferSmall(2,2,32)` | 2-in / 2-out | 64,394 | 37 |
| `withdraw.circom` | `CheckNullifiersInputsOutputsValueIMT(2,1,32)` | 2-in / 1-out | 54,319 | 26 |
| `disburse.circom` | `Zeto(1,16,32)` | 1-in / 16-out | 208,719 | 11 |
| `disburse256.circom` | `Zeto(1,256,32)` | 1-in / 256-out | 2,796,719 | 11 |

Constraint counts measured 2026-07-27 (`snarkjs r1cs info` over `circuits/out/*.r1cs`).
`disburse.circom` is the dev-loop instantiation of the *same* base as `disburse256.circom`; the
live pool carries the 256 verifier. Note that the dev-loop one is not optional collateral: a public
count is a per-base property, so an envelope change regenerates **five** verifier/zkey pairs.

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

**withdraw — `uint[26]`**

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
| `lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom` (transfer) | lines 103–104 | line 117 |
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
  `c1 − c2 = m1 − m2`. `assertDistinctOwnerPubkeys` (`packages/core/src/note.ts`) rejects
  duplicates before proving. transfer is exempt since U-X3 (§11-8 v1.1): its base encrypts
  receiver ciphertext `i` under `encryptionNonce + i` in-circuit
  (`encrypt-outputs-per-output-nonce.circom`), so duplicate owners — including a self-send — are
  structurally safe, and receivers decrypt `ct_i` with `nonce + i`. deposit is exempt too: both
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

`prove_all.sh` passes three roots — `-l "$ZETO" -l "$CIRCOMLIB" -l lib`, with
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
