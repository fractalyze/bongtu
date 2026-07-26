# Zeto derivation

bongtu is built on [Zeto](https://github.com/hyperledger-labs/zeto) (Apache-2.0, © Kaleido). This
page records what was taken, what was deliberately not taken, and every modification with its
consequence. Every row is checkable file-by-file against the pinned upstream checkout `2c8ce6b`
(2026-07-16).

## One flavor, and what is omitted

bongtu uses a single Zeto flavor — `anon_enc_nullifier_non_repudiation` (anonymous, encrypted
outputs, nullifier spend, mandatory authority envelope). What is not ported, and what stands in its
place:

| upstream feature | bongtu instead |
|---|---|
| 12 flavor contracts (anon, enc, kyc, burnable, qurrency, nf, …) | one flavor; `BongtuPool` is the only pool contract |
| issuer `mint` | wrapped ERC-20 only; `deposit` mints notes 1:1 against escrow |
| UTXO locking (DvP / escrow) | no lock/unlock path exists in `BongtuPool` |
| KYC registry | replaced by the admin app's role model |
| value-keyed SMT | replaced by a unified single-frontier IMT: the 256-out batch disburse needs contiguous-index subtree attach, which an SMT cannot do |

The **circuits are copied and modified** (below). `BongtuPool` shares no code with Zeto's contracts:
it is a purpose-built rewrite over storage Zeto's tree does not have. It carries the flavor's three
duties, each locatable in `contracts/src/BongtuPool.sol` — proof binding (`verifyProof` on all four
ops, with `authorityPublicKey` injected from storage and, on the three spending ops, `enabled[i]`
derived by the contract from the proof's own nullifiers rather than taken from calldata; deposit has
no `enabled` signal), nullifier spend
(`nullifierUsed` + `_spendNullifier`), and non-repudiation envelope emission (`Deposited` /
`Transferred` / `Withdrawn` / `Disbursed` + `DisburseCiphertexts`). Details:
[contracts.md](contracts.md).

## Circuit provenance

Sub-gadgets (`CheckHashes`, `CheckNullifiers`, `CheckSum`, `CheckPositive`, `EncryptOutputs`,
`SymmetricEncrypt`, `Ecdh`, `BabyPbk`) are **not vendored** — they resolve via `circom -l` into the
pinned upstream checkout, so they are byte-identical to upstream by construction
([toolchain.md](toolchain.md#include-resolution-roots)). The membership- and envelope-bearing bases are
vendored into `circuits/lib/` and modified:

| bongtu file | upstream source | verdict | deliberate deltas |
|---|---|---|---|
| `deposit.circom` + `lib/deposit_authority_imt_base.circom` | `lib/deposit.circom` | faithful derivation | added in-circuit authority envelope (18-public surface) |
| `transfer.circom` + `lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom` | `basetokens/anon_enc_nullifier_non_repudiation_base.circom` | faithful derivation | SMT→IMT membership, depth 64→32; value belt; zero-commitment guard. Upstream's `cipherTexts` / `cipherTextAuthority` outputs are kept — 36-public surface |
| `withdraw.circom` + `lib/check-nullifiers-value-imt-base.circom` | `lib/check-nullifiers-value-base.circom` | faithful derivation | SMT→IMT membership; value belt; zero-commitment guard; `GreaterEqThan(100)→(101)` completeness fix; authority envelope |
| `disburse.circom` / `disburse256.circom` + `lib/anon_enc_nullifier_non_repudiation_imt_base.circom` | `basetokens/anon_enc_nullifier_non_repudiation_base.circom` | derived, structurally | SMT→IMT membership; zero-commitment guard; **added** depth-`log2(B)` subtree gadget with public `subtreeRoot`; **added** public `disclosureHash`; upstream's `cipherTexts` / `cipherTextAuthority` outputs **removed** (ciphertext is bound by `disclosureHash` instead) — 10-public surface; 16- and 256-arity instantiations |

`GreaterEqThan(100)→(101)`: summing two 100-bit inputs can reach 2^101, which violates
`GreaterEqThan(100)`'s `< 2^100` precondition and would make honest near-maximum withdrawals lose
their witness.

The two non-repudiation bases form a chain, not a pair of siblings: the transfer base's header cites
`anon_enc_nullifier_non_repudiation_imt_base.circom` — the disburse base's original — as its parent
and lists what it drops from it (the subtree gadget and `disclosureHash`). The `upstream source`
column above names the tracked upstream file both ultimately descend from. **No upstream constraint
is silently dropped** — every delta above is written down in the vendored file, either in its header
or inline at the constraint's own call site (the value belt and the zero-commitment guard are
documented in the body, next to the constraints they add).

## Project-authored circuit files

Three load-bearing circuit files are **not** upstream — a fresh clone of hyperledger-labs/zeto does
not contain them. The two `circuits/lib/` ones originated as git-untracked local files inside the
Zeto checkout that the bongtu build nonetheless depended on via `-l`; they now live here with
provenance headers:

- `check-imt-proof.circom` — the IMT membership gadget (`CheckIMTProof`; the single definition in
  this repo), derived from Zeto's SMT gadgets. Load-bearing for the live verifier.
- `anon_enc_nullifier_non_repudiation_imt_base.circom` — the disburse base, derived from Zeto's
  non-repudiation SMT base.
- `circuits/disburse256.circom` — the bongtu-authored 256 top-level, which supersedes the formerly
  untracked `run_nonrep_imt_256.circom`.

Consequence: a fresh checkout builds every circuit with no dependency on any untracked Zeto file.
For the two `lib/` files the mechanism is the include spelling — both are reached by bare name, which
has no counterpart at the `$ZETO` root, so only `-l lib` can resolve them
([circuits.md](circuits.md#structure-and--l-resolution)). `disburse256.circom` needs no such
mechanism: it is a top-level compiled by path from `circuits/`, and lives here.

## The SMT→IMT swap and its soundness debt

Swapping a value-keyed SMT for an index-keyed IMT turns an upstream non-issue into a
mint-from-nothing. `CheckHashes` has a zero-commitment escape — at `commitment == 0` the value, salt
and owner go unbound — which is sound in stock Zeto only because a value-keyed tree makes a zero
commitment structurally impossible as a member. bongtu's IMT commits `zeros[0] = 0` at every
position ahead of the frontier and at every disburse pad slot, so `0` is a genuine,
membership-provable leaf. Hence the guard `enabled[i] * IsZero(inputCommitments[i]) === 0` on every
spending base, disburse included. Full exploit trace and the companion value belt:
[security-model.md](security-model.md#why-the-zero-commitment-guard-exists) and
[circuits.md](circuits.md#soundness-invariants).

Two contract-side notes on the same theme: zero output commitments are rejected on write for
deposit, transfer and withdraw (`ZeroOutputCommitment`; a disburse's pad slots are zero leaves by
construction and are not written as output commitments), and output uniqueness is
deliberately absent, because duplicate outputs share one nullifier and are therefore a self-burn,
not a soundness hole ([contracts.md](contracts.md#output-commitments)).

## Upstream pin

The Zeto checkout is at `2c8ce6b` (2026-07-16) with zero tracked-file modifications, and no upstream
commit has touched `zkp/circuits` since — so every `-l`-resolved include matches what bongtu derived
from. (Upstream has since moved org to LFDT-Paladin; the redirect is intact.)
