# Zeto derivation & provenance

Why bongtu carries so little Solidity compared to [Zeto](https://github.com/hyperledger-labs/zeto)'s dozen+
contracts, exactly which upstream files each bongtu circuit derives from, and the modifications made (with
their soundness consequences). Audited file-by-file against the pinned upstream checkout
(`2c8ce6b`, 2026-07-16) on 2026-07-24.

## Which Zeto we use, and what we deliberately dropped

bongtu uses **one** Zeto flavor — `anon_enc_nullifier_non_repudiation` (anonymous, encrypted outputs,
nullifier-based spend, mandatory authority envelope). Zeto ships ~12 flavor contracts plus shared
infrastructure; every piece we did **not** port maps 1:1 to a locked SPEC decision, not an oversight:

| Upstream Zeto feature | Why bongtu omits it |
|---|---|
| 12 flavor contracts (anon, enc, kyc, burnable, qurrency, nf…) | SPEC Q1: single flavor |
| Issuer `mint` | SPEC Q3: wrapped ERC-20 only; deposit mints notes 1:1 |
| UTXO locking (DvP / escrow) | Out of scope (payroll, not settlement) |
| KYC registry | Replaced by the §7 admin role-model |
| Value-keyed SMT tree | **Replaced by a unified single-frontier IMT** — the 256-out batch disburse (the product headline) needs contiguous-index subtree attach, which an SMT cannot do |

**Decision (recorded, do not re-litigate):** we did NOT wholesale-copy a flavor contract and layer on top.
The upstream flavor contract is a per-transfer token over a tree bongtu replaces entirely, so a copy would
carry 12 dead flavors, still require rewriting the tree, and reset the security narrative already built on
`BongtuPool`. Instead the **circuits are copied+modified** (below) and `BongtuPool` is a **purpose-built
rewrite** with audited semantic parity of the flavor's duties (proof binding, nullifier spend, non-repudiation
envelope emission). Audit verdict on the contract pair: `divergent_rewrite`, zero flavor duty lost.

## Circuit provenance (audited)

Sub-gadgets (`CheckHashes`, `CheckNullifiers`, `CheckSum`, `CheckPositive`, `EncryptOutputs`,
`SymmetricEncrypt`, `Ecdh`, `BabyPbk`, `deposit`) are **not vendored** — they resolve via `circom -l` into the
pinned upstream checkout, so they are byte-identical to upstream by construction. Only the two membership-bearing
bases are vendored and modified:

| bongtu file | Upstream source | Verdict | Deliberate deltas |
|---|---|---|---|
| `circuits/deposit.circom` | `lib/deposit.circom` (tracked) | verbatim | none (0-in, no envelope — v1 gap §11-1) |
| `circuits/transfer.circom` + `lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom` | `basetokens/anon_enc_nullifier_non_repudiation_base.circom` (tracked) | faithful derivation | SMT→IMT membership; added value-belt; depth 64→32; **identical 36-public surface** |
| `circuits/withdraw.circom` + `lib/check-nullifiers-value-imt-base.circom` | `lib/check-nullifiers-value-base.circom` (tracked) | faithful derivation | SMT→IMT membership (only); `GreaterEqThan(100)→(101)` completeness fix; added value-belt |
| `circuits/disburse.circom` / `disburse256.circom` | `run_nonrep_imt_256.circom` (**untracked**, see below) | verbatim/derived | 256-arity instantiation of the same base |

Audit conclusion: **no upstream constraint is silently dropped.** Every delta has a written rationale (file
headers, `docs/milestone-m0.md`, `THIRD_PARTY_NOTICES.md`) and the comment-stripped diffs reduce to exactly the
declared modifications.

## Provenance gap being fixed (Unit 0)

Three load-bearing circuit files that bongtu's build depends on via `-l $ZETO` are **git-untracked local
files inside the zeto checkout** — they are NOT upstream hyperledger-labs/zeto files, and are under no version
control anywhere:

- `lib/check-imt-proof.circom` — the IMT membership gadget (defines `CheckIMTProof`; nothing else on disk
  defines it), load-bearing for the **live** GIWA verifier.
- `basetokens/anon_enc_nullifier_non_repudiation_imt_base.circom` — the 256 IMT base.
- `run_nonrep_imt_256.circom` — the disburse-256 top-level.

A fresh `git clone` of zeto does not contain them → the build breaks, and a silently different substitute
would change the verifying key. **Resolution:** vendor all three into `circuits/lib/` with provenance headers
(project-authored, derived-from-Zeto-SMT-gadget), and correct the "Reusable sources" wording in
`docs/toolchain.md` that misattributes them to upstream.

## Critical finding: the SMT→IMT swap reopened a mint-from-nothing (fixed in Unit 0)

The audit surfaced, and 3/3 independent adversarial verifiers confirmed, a **critical soundness break** the
M0 value-belt does not cover:

- Upstream `CheckHashes` has a **zero-commitment escape** (`commitment==0` ⇒ value/salt/owner unbound). This
  is sound in stock Zeto ONLY because its **value-keyed SMT** makes a 0-commitment structurally impossible as
  a member.
- bongtu's **index-keyed IMT** commits `zeros[0]=0` at every position ahead of the frontier and at every
  disburse pad slot, so **0 is a genuine, membership-provable member**. `leafIndices` is a separate
  prover-controlled input.
- Therefore an attacker spends a padded 0-leaf declaring **arbitrary value X**: CheckHashes escapes (no value
  binding), CheckNullifiers binds a fresh nullifier `Poseidon3(X,salt,sk)`, membership holds (`enabled=1`),
  the value-belt `(1-enabled)*value===0` is vacuous at `enabled=1`, CheckSum yields `out=X`. Permissionless
  `withdraw`/`transfer` drain, repeatable. No real funds at risk (testnet, mock kKRW), but the contract is
  unsound.

**Fix (Unit 0):** add `enabled[i] * IsZero(inputCommitment[i]) === 0` (forbid a zero-commitment enabled input)
to the transfer, withdraw, **and disburse** bases — restoring the SMT's implicit invariant explicitly.
Because this changes the disburse r1cs, the reused **1.24 GB disburse-256 zkey must be regenerated** (the
byte-identity/reuse plan is retired). See [[imt-membership-breaks-zeto-zero-commitment-escape]]. Two lower-risk
contract gaps ride along: no `outputCommitment != 0` check and no output-uniqueness check (upstream
`validateOutputs`) — both self-burn only, added defensively.

## Upgradeability

Upstream flavor contracts are UUPS-upgradeable (`_authorizeUpgrade`, diamond storage, `factory_upgradeable`).
`BongtuPool` was a plain `Ownable2Step` with immutable verifiers — which is exactly why the Unit 0 security
fix forces a **redeploy** rather than an upgrade. **Decision:** the Unit-0 redeploy goes out behind a UUPS
(ERC-1967) proxy so this is the last forced redeploy; owner is a single key on testnet, a multisig/timelock on
mainnet (as Zeto's own docs recommend).

## No post-derivation upstream drift

The zeto checkout HEAD == origin/main == `2c8ce6b` (2026-07-16), before the 2026-07-23/24 vendoring, with zero
tracked-file modifications; the GitHub API shows no commits touching `zkp/circuits` since. So every
`-l`-resolved upstream include matches what bongtu derived from — no silent upstream change postdates our work.
Note: upstream moved org to LFDT-Paladin (redirect intact); `README.md` / `NOTICE` links to update at leisure.
