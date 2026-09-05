# Circuits

Two circuit families share one pool. The **enterprise** family — arbiter envelope mandatory,
verified by `BongtuPool` itself — is seven top-level circuits over four bases; the **consumer**
(no-auditor) family adds six more tops over four sibling bases
([below](#consumer-circuits-and-public-surfaces)). Both share one membership gadget and one
envelope construction. Sources: `circuits/*.circom` (top-levels) and `circuits/lib/*.circom`
(vendored bases). Provenance against upstream Zeto is in
[zeto-derivation.md](zeto-derivation.md); build commands are in [toolchain.md](toolchain.md).

| circuit | template | arity | constraints | publics | domain |
|---|---|---|---|---|---|
| `deposit.circom` | `BongtuDepositAuthority(2)` | 0-in / 2-out | 14,127 | 19 | 2^14 |
| `transfer.circom` | `ZetoTransferSmall(2,2,32)` | 2-in / 2-out | 64,394 | 37 | 2^16 |
| `transfer10.circom` | `ZetoTransferSmall(10,10,32)` | 10-in / 10-out | 261,683 | 141 | 2^18 |
| `transfer10x2.circom` | `ZetoTransferSmall(10,2,32)` | 10-in / 2-out | 212,386 | 68 | 2^18 |
| `withdraw.circom` | `BongtuWithdraw(2,1,32)` (wraps `CheckNullifiersInputsOutputsValueIMT`, adds public `recipient`) | 2-in / 1-out | 54,320 | 27 | 2^16 |
| `disburse.circom` | `Zeto(1,16,32)` | 1-in / 16-out | 208,719 | 11 | 2^18 |
| `disburse256.circom` | `Zeto(1,256,32)` | 1-in / 256-out | 2,796,719 | 11 | 2^22 |

Constraint counts measured 2026-07-28 (`snarkjs r1cs info` over `circuits/out/*.r1cs`). The live
pool carries the 256 verifier. `disburse.circom` is the dev-loop instantiation of the *same* base
as `disburse256.circom`; `transfer10.circom` and `transfer10x2.circom` are `transfer.circom`'s
base at other arities. The dev-loop disburse is not optional collateral: a public count is a
per-base property, so an envelope change regenerates **seven** verifier/zkey pairs.

**transfer10x2 exists because outputs, not inputs, are what a spend pays for on chain.** Each
output is a depth-32 IMT leaf append (~0.93M gas), and on a real spend eight of transfer10's ten
outputs are zero-value padding — `transfer10` measured 11,592,399 gas, ~9.3M of it those appends.
Dropping to two outputs (payment + change, or merged note + zero change) keeps the ten-note
consolidation and sheds the padding. The input side — ten membership proofs — is unchanged, which
is also why the constraint saving is only ~19%.

**transfer10 has almost no headroom.** snarkjs picks `domainSize = 2^(floor(log2(nConstraints +
nPublic)) + 1)`, so transfer10 stays at 2^18 only while `nConstraints <= 262,002` — **319
constraints of margin**. Anything added to `ZetoTransferSmall` (an extra hash, one more range
check) spills it to 2^19, which doubles the zkey and the proving time. Measure before and after
any base change. transfer10x2 shares the 2^18 domain with 49,689 constraints of margin — cutting
eight outputs does not reach 2^17, because 2^17 caps at ~131k and the ten membership proofs alone
exceed that.

## The hybrid envelope key

All four enterprise bases key `SymmetricEncrypt` with a fold of the classical ECDH secret and an
ML-KEM-768 shared secret; the derivation, tags and limb encoding are owned by
[protocol.md](protocol.md#the-hybrid-envelope-key). What the circuits contribute:

- `kemSs[2]` is a **private witness**, range-checked in-circuit with `Num2Bits(128)`
  (canonical-limb hygiene).
- `kemBinding` is a **public output** computed from that witness, so a prover cannot claim a
  binding inconsistent with the secret it encrypted under; the alarm-enforced trade-off is in
  [security-model.md](security-model.md#post-quantum-the-hybrid-authority-envelope-key).
- `kemBinding` is declared as the **last** circuit output, which is why every existing output
  index is unchanged and every public-*input* index shifted by exactly one when the envelope
  went hybrid.

There is no ECDH-only encryption path left in any base. Receiver-side `EncryptOutputs` is
untouched.

## Public surfaces

circom orders public signals as circuit **outputs first** (declaration order), then the top-level
`public` inputs (declaration order). The contract — or, for the consumer family, the module —
indexes into these vectors literally, so any reordering is a breaking change requiring a new
verifier and a pool upgrade or module swap. The exhaustive per-op index tables live in
[`.dev/circuit-surfaces.md`](../.dev/circuit-surfaces.md). Two signals worth knowing without the
tables:

- **withdraw `pub[26]` is `recipient`** — the L1 payout address as a field element; the contract
  range-checks uint160 and pays it instead of msg.sender, which is what makes the stealth exit
  relayable ([relayer.md](relayer.md)).
- **disburse publishes neither its batch ciphertext nor the 1088-byte `kemCiphertext`** in the
  public vector: the former travels as a separate calldata argument bound by `disclosureHash`,
  the latter as a `bytes` argument bound by `kemBinding` ([protocol.md](protocol.md),
  [contracts.md](contracts.md)).

## Consumer circuits and public surfaces

The consumer (no-auditor) family: six tops over four sibling bases, each base derived from a
vendored enterprise base above with the parent untouched — per-file provenance and deltas in
[zeto-derivation.md](zeto-derivation.md#the-consumer-no-auditor-family), design record in
`.dev/op-module-design.md` (OPMOD §2/§3). These circuits are verified by op **modules**, not the
pool ([contracts.md](contracts.md#the-op-module-layer)).

| circuit | template | arity | constraints | publics | domain |
|---|---|---|---|---|---|
| `depositPriv.circom` | `BongtuConsumerDeposit(2)` | 0-in / 2-out | 20,509 | 16 | 2^15 |
| `transferPriv.circom` | `BongtuConsumerTransfer(2,2,32)` | 2-in / 2-out | 60,704 | 20 | 2^16 |
| `transfer10x2Priv.circom` | `BongtuConsumerTransfer(10,2,32)` | 10-in / 2-out | 204,984 | 36 | 2^18 |
| `withdrawPriv.circom` | `BongtuWithdrawPriv(2,1,32)` | 2-in / 1-out | 52,614 | 16 | 2^16 |
| `disbursePriv.circom` | `BongtuConsumerDisburse(1,16,32)` | 1-in / 16-out | 214,769 | 8 | 2^18 |
| `disbursePriv256.circom` | `BongtuConsumerDisburse(1,256,32)` | 1-in / 256-out | 3,049,889 | 8 | 2^22 |

Constraint counts measured 2026-09-03. `transferPriv` lands at 2^16 with ~4.8k of margin,
resolving the spec's TIGHT flag; `disbursePriv` is the dev-loop instantiation of the same base as
`disbursePriv256` (the enterprise disburse/disburse256 pattern — an envelope change on this base
regenerates both pairs). The deprecated `transfer10` has no consumer twin.

Versus its enterprise twin, every consumer top **drops** `cipherTextAuthority[·]`, `kemBinding`
and `authorityPublicKey[2]` — there is no authority material anywhere in the family — and
**adds** `viewTags[nOut]` as the last output run; `depositPriv` and `withdrawPriv` additionally
gain receiver ciphertexts their twins never had (the enterprise deposit publishes only an
authority envelope; the enterprise withdraw's change note is arbiter-recoverable). Receiver
encryption is the hybrid per-output construction (ECDH against the recipient's note-layer VIEW
key folded with a per-output ML-KEM-768 secret, nonce `encryptionNonce + i`, uniform across all
six shapes). Every input-side soundness constraint of the section below survives each base edit
verbatim; the per-circuit preservation table is OPMOD §2.1. Index layouts:
[`.dev/circuit-surfaces.md`](../.dev/circuit-surfaces.md#consumer-module-verified). The batch's
6·B-element `disclosure` array and every circuit's per-recipient 1088-byte KEM ciphertexts ride
module calldata, not the public vector; the on-chain checks they get are the module's
([contracts.md](contracts.md#the-op-module-layer)).

## Soundness invariants

Three constraints guard the input side. They are not implied by one another, nor by the
contract's `enabled` injection.

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
`enabled[0] = 1` on every accepted call and the value belt is vacuous there. The guard is not —
see below.

**Value belt.** `CheckHashes` and `CheckNullifiers` both accept a zero commitment / zero nullifier
with *any* value, and `CheckSum` adds `inputValues[i]` unconditionally. A fabricated input
`{nullifier: 0, commitment: 0, value: X, enabled: 0}` would otherwise satisfy every other
constraint and inflate the output sum. Binding value to `enabled` — which the contract derives as
`nullifier != 0` — makes that witness unsatisfiable: `nullifier = 0 ⇒ enabled = 0 ⇒ value = 0`;
`nullifier ≠ 0 ⇒ enabled = 1 ⇒ real membership required.`

**Zero-commitment guard.** `enabled = 1` is not covered by the value belt. The index-keyed IMT
commits `zeros[0] = 0` at every position ahead of the frontier and at every disburse pad slot, so
`0` is a genuine, membership-provable leaf — the upstream `CheckHashes` zero-commitment escape
becomes a mint-from-nothing. Rationale in [security-model.md](security-model.md); the exploit
trace lives there, not here. `disburse` carries the guard because its single input is always
`enabled = 1`, so the guard is the only thing standing between a compromised discloser and a mint
from a zero leaf.

Two further invariants live outside the circuits and must be enforced by whoever assembles a
witness:

- **Distinct output owner pubkeys (disburse only).** All outputs of a disburse batch share one
  ephemeral key and one `encryptionNonce`, so two outputs to the same owner leak
  `c1 − c2 = m1 − m2`. `assertDistinctOwnerPubkeys` (`packages/core/src/notes/note.ts`) rejects
  duplicates before proving. The transfer arities are exempt since U-X3 (§11-8 v1.1): their base
  encrypts receiver ciphertext `i` under `encryptionNonce + i` in-circuit
  (`encrypt-outputs-per-output-nonce.circom`), so duplicate owners — a self-send, or a merge
  whose outputs all share one key — are structurally safe, and receivers decrypt `ct_i` with
  `nonce + i`. deposit is exempt too: both its outputs belong to the depositor and it publishes
  no per-recipient ciphertext, only a single authority envelope over both.
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

`build/prove_all.sh` passes three roots — `-l "$ZETO" -l "$CIRCOMLIB" -l lib`, with `CIRCOMLIB`
defaulting to `$ZETO/node_modules`. Only two do work:

| `-l` root | resolves |
|---|---|
| `$ZETO` | the `lib/`-prefixed upstream sub-checks **and** the `node_modules/`-prefixed circomlib includes |
| `lib` (repo-relative) | every bare-name include — the four vendored bongtu bases plus `check-imt-proof.circom`, i.e. all five files in `circuits/lib/` |
| `$ZETO/node_modules` | nothing — no include in the closure is spelled `circomlib/circuits/...` |

Self-containment on the membership and envelope path comes from the *spelling*, not the search
order (`lib` is passed last): the bare names have no counterpart at the `$ZETO` root, so only
`-l lib` can supply them, and no untracked file in the Zeto checkout is load-bearing
([zeto-derivation.md](zeto-derivation.md#project-authored-circuit-files)). The upstream
sub-checks stay resolved out of the pinned checkout, so they are byte-identical to upstream by
construction.

How to build, prove and run the attack gates is owned by
[`circuits/README.md`](../circuits/README.md); exact invocations are in
[toolchain.md](toolchain.md).
