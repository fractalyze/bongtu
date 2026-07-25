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

The **circuits are copied+modified** from upstream (below); `BongtuPool` is a **purpose-built rewrite** with
audited semantic parity of the flavor's duties (proof binding, nullifier spend, non-repudiation envelope
emission). A wholesale flavor-contract copy would carry 12 unused flavors over a tree bongtu replaces
entirely, and would discard the security analysis already built on `BongtuPool`. Audit verdict on the
contract pair: `divergent_rewrite`, zero flavor duty lost.

## Circuit provenance (audited)

Sub-gadgets (`CheckHashes`, `CheckNullifiers`, `CheckSum`, `CheckPositive`, `EncryptOutputs`,
`SymmetricEncrypt`, `Ecdh`, `BabyPbk`) are **not vendored** — they resolve via `circom -l` into the
pinned upstream checkout, so they are byte-identical to upstream by construction. The membership- and
envelope-bearing bases are vendored (in `circuits/lib/`) and modified:

| bongtu file | Upstream source | Verdict | Deliberate deltas |
|---|---|---|---|
| `circuits/deposit.circom` + `lib/deposit_authority_imt_base.circom` | `lib/deposit.circom` (tracked) | faithful derivation | added in-circuit authority envelope (18-public surface, SPEC §6b) |
| `circuits/transfer.circom` + `lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom` | `basetokens/anon_enc_nullifier_non_repudiation_base.circom` (tracked) | faithful derivation | SMT→IMT membership; added value-belt; depth 64→32; **identical 36-public surface** |
| `circuits/withdraw.circom` + `lib/check-nullifiers-value-imt-base.circom` | `lib/check-nullifiers-value-base.circom` (tracked) | faithful derivation | SMT→IMT membership (only); `GreaterEqThan(100)→(101)` completeness fix; added value-belt |
| `circuits/disburse.circom` / `disburse256.circom` | `run_nonrep_imt_256.circom` (**untracked**, see below) | verbatim/derived | 256-arity instantiation of the same base |

Audit conclusion: **no upstream constraint is silently dropped.** Every delta has a written rationale (file
headers, `.dev/milestone-m0.md`, `THIRD_PARTY_NOTICES.md`) and the comment-stripped diffs reduce to exactly the
declared modifications.

## Project-authored files vendored in `circuits/lib/`

Three load-bearing circuit files are **project-authored, not upstream** — a fresh `git clone` of
hyperledger-labs/zeto does not contain them (the two `circuits/lib/` files originated as git-untracked
local files inside the zeto checkout; the third is a bongtu-authored top-level). They live in the bongtu
repo with provenance headers:

- `circuits/lib/check-imt-proof.circom` — the IMT membership gadget (defines `CheckIMTProof`; nothing else on
  disk defines it), derived from Zeto's SMT gadgets, load-bearing for the **live** GIWA verifier.
- `circuits/lib/anon_enc_nullifier_non_repudiation_imt_base.circom` — the 256 IMT base, derived from Zeto's
  non-repudiation SMT base.
- the disburse-256 top-level — `circuits/disburse256.circom`, which instantiates the vendored base
  (it supersedes the formerly untracked `run_nonrep_imt_256.circom`).

The build resolves them via `-l lib`; no untracked zeto file is load-bearing.

## The zero-commitment guard (SMT→IMT soundness invariant)

The transfer, withdraw, **and disburse** bases each carry

```
enabled[i] * IsZero(inputCommitments[i]) === 0;   // enabled=1 => inputCommitment != 0
```

forbidding a zero-commitment enabled input. The guard exists because the SMT→IMT swap turns an upstream
non-issue into a mint-from-nothing (found in audit, confirmed by 3/3 independent adversarial verifiers):

- Upstream `CheckHashes` has a **zero-commitment escape** (`commitment==0` ⇒ value/salt/owner unbound). This
  is sound in stock Zeto ONLY because its **value-keyed SMT** makes a 0-commitment structurally impossible as
  a member.
- bongtu's **index-keyed IMT** commits `zeros[0]=0` at every position ahead of the frontier and at every
  disburse pad slot, so **0 is a genuine, membership-provable member**. `leafIndices` is a separate
  prover-controlled input.
- Without the guard, an attacker spends a padded 0-leaf declaring **arbitrary value X**: CheckHashes escapes
  (no value binding), CheckNullifiers binds a fresh nullifier `Poseidon3(X,salt,sk)`, membership holds
  (`enabled=1`), the value-belt `(1-enabled)*value===0` is vacuous at `enabled=1`, CheckSum yields `out=X` —
  a repeatable permissionless drain.

The guard restores the SMT's implicit invariant explicitly. See
[[imt-membership-breaks-zeto-zero-commitment-escape]]. The contract additionally rejects zero output
commitments (`ZeroOutputCommitment`) — a self-burn-only gap, closed defensively. Upstream
`validateOutputs`' other duty — output-uniqueness — is **deliberately absent**: duplicate output
commitments share one nullifier, so every copy past the first is unspendable — self-burn only, no
soundness impact.

## Upgradeability

`BongtuPool` is deployed behind a **UUPS (ERC-1967) proxy** (`contracts/src/BongtuPool.sol` inherits
`UUPSUpgradeable`; proxy + impl addresses in `deploy/addresses.91342.json`), so a future circuit/verifier
change ships as an upgrade, not a redeploy. Upstream flavor contracts are likewise UUPS-upgradeable. The
proxy owner is a single key on testnet; mainnet calls for a multisig/timelock (as Zeto's own docs recommend).

## No post-derivation upstream drift

The zeto checkout HEAD == origin/main == `2c8ce6b` (2026-07-16), before the 2026-07-23/24 vendoring, with zero
tracked-file modifications; the GitHub API shows no commits touching `zkp/circuits` since. So every
`-l`-resolved upstream include matches what bongtu derived from — no silent upstream change postdates our work.
Note: upstream moved org to LFDT-Paladin (redirect intact); `README.md` / `NOTICE` links to update at leisure.
