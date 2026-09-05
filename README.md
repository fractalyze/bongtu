# bongtu (봉투)

[![ci](https://github.com/fractalyze/bongtu/actions/workflows/ci.yml/badge.svg)](https://github.com/fractalyze/bongtu/actions/workflows/ci.yml)

A private stablecoin transfer layer for institutions, built on
[Zeto](https://github.com/hyperledger-labs/zeto) with **enforced auditor disclosure**. Private
peer-to-peer transfers already exist; no one has made **private payments work at scale**. bongtu
does: one transaction pays up to **256 recipients**, so a 100,000-person payroll settles in minutes
for a few dollars, every amount hidden from the public and readable by an auditor.

A digital 월급봉투: everyone sees the envelopes handed out, only the recipient sees the amount
inside, and a designated authority can open every envelope. Each is encrypted to a fixed authority
key **inside the ZK proof** (non-repudiation), so a regulator can decrypt sender/receiver/amount for
any transaction while the public chain and other users cannot.

## The problem

Stablecoins settle **tens of trillions of dollars a year** — more raw volume than PayPal and on the
order of Visa ([a16z](https://a16zcrypto.com/posts/article/state-of-crypto-report-2025/)). For them
to carry everyday money (salaries, vendor payments, payouts), no one's income or spending can be
public, and paying many people must stay fast and cheap. A public chain gives neither: it exposes
*"individual salaries, bonus structures, and corporate treasury balances to public view,"* and
existing private systems can't do a large payout without splitting it into hundreds of transactions.

When you use a bank, you take four things for granted:

|   | You expect… | Public stablecoin | **bongtu** |
|---|---|---|---|
| 1 | your balance & history are yours alone | ❌ world-readable | ✅ |
| 2 | outsiders can't see how much you send | ❌ every amount public | ✅ |
| 3 | outsiders can't see who you send to | ❌ every transfer public | ✅ |
| 4 | but a regulator can still audit you | ⚠️ only by exposing everything | ✅ built into every tx |

A public stablecoin fails the first three. Privacy tools (mixers like Tornado) fix those but lack
built-in auditability, which is why [Tornado Cash was
sanctioned](https://home.treasury.gov/news/press-releases/jy0916). These four are the basic
requirements; bongtu meets them **at scale**, across a payroll-sized payout in a single transaction.

## Comparison with others

Verified against each project's source and deployed artifacts:

| | **bongtu** | Zeto | Railgun | zkBob | Token-2022 |
|---|---|---|---|---|---|
| P2P transfer | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **Mass payout / tx** | ✅ **256** | 10 | 5 | 127 | ❌ |
| Hides amount | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hides graph (from↔to) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Hides recipient count | ✅ padded to 256 | ⚠️ | ⚠️ | ⚠️ | ❌ |
| **Involuntary audit** | ✅ circuit-enforced | ✅ | ❌ voluntary | ❌ voluntary | ✅ |
| Per-period disclosure | ✅ epoch rotation | ❌ | ❌ | ❌ | ❌ |
| Post-quantum (HNDL) | ✅ hybrid ML-KEM | ⚠️ | ❌ | ❌ | ❌ |
| Own-notes lookup | ✅ indexer `/notes` | ❌ scan all | ❌ scan all | ❌ scan all | n/a |
| Live | ✅ | ✅ | ✅ | ❌ sunset | ✅ |

- Railgun's 5 rises to 13 only when spending a single input; zkBob's 127 shipped, but its pools are
  shut down.
- **Post-quantum**: all three encrypt on-chain, but Railgun (ECDH) and Token-2022 (ElGamal) use
  classical crypto whose keys stay on-chain forever, so a future quantum computer could decrypt every
  past amount. bongtu mixes in a lattice (ML-KEM-768) secret, so breaking the classical half alone
  reveals nothing.

The bottom three rows are what no live system offers together: audit that is both enforced and
scoped, post-quantum on-chain ciphertext, and a per-user note lookup instead of scanning the whole
pool.

## The headline: mass private disbursement

One transaction pays up to **256 recipients**, each with an amount only they and the auditor can
read.

**How the 256 fit in one transaction.** The disburse circuit proves, in a single proof, that the 256
output notes already form a depth-8 subtree, together with value conservation (the input note equals
the sum of the outputs). The contract then grafts that whole subtree onto the main Merkle tree at
level 8 — **O(log 256)** instead of appending 256 leaves one at a time, which is O(256) and would
not fit in a block. It pads the batch to a fixed 256 with no per-leaf event (so the real recipient
count stays hidden) and publishes all 256 ciphertexts on-chain for the auditor, bound by one
aggregated disclosure hash the proof commits to.

One such batch, measured live against the same circuits and the same hybrid ML-KEM envelope:
**3,905,519 L2 gas** — **15,256 per recipient**. That measurement was taken two chains back and
has not been re-run since (on Base Sepolia or on the current Maroo deployment); it carries over
because no chain move changed an executable line in any operation path, only the initializer
([`docs/performance.md`](docs/performance.md) shows the check). The other four operations were
re-measured on Base Sepolia and are in that file.

A **100,000-person payroll** is 391 of those batches, priced at the measuring chain's own 0.006 gwei
quote — not at the higher gas price our deploy scripts pin for themselves:

| | per 256-batch | ×391 (100,000 people) |
|---|---|---|
| L2 gas | 3,905,519 | 1,527,057,929 |
| L2 cost @ 0.006 gwei | ≈2.343e-5 ETH | **0.009162 ETH** |
| L1 data fee | ≈1.0e-7 ETH | **0.000039 ETH** |
| **total** | | **0.009201 ETH** — about **$27.60** at $3000/ETH |
| GPU proving @ 0.47 s | 0.47 s | **≈3.1 minutes** |

A full private payroll of 100,000 clears in **a few minutes for well under $50**, proving on a
single GPU. For contrast, Zeto's own published number is 2,763,071 gas for **2 recipients**
(~1.38M each), making bongtu **~90× cheaper per recipient**: we replaced Zeto's value-keyed SMT
with an IMT batch-attach and its per-note ciphertext with one aggregated disclosure hash. *(These
are 391× one measured batch, not a single live 100k run.)*

## What is built

Every surface below is built. The wallet path ran end to end against the retired Base Sepolia
deployment (deposits, a `transfer10x2` merge and a `transfer10x2` payment landed; the arbiter
indexer surfaced the resulting notes). The fresh Maroo pool in [Status](#status) has passed its
deploy smoke — a real proof-carrying deposit — but the app flows and the 256-recipient disburse
have not been re-run on it yet.

| surface | what it is |
|---|---|
| [**Bongtu Wallet**](https://bongtu.fractalyze.io) | The institution wallet (`apps/treasury-web`): self-custody, spending key derived from a MetaMask signature, proofs generated in the browser, private balance / send / withdraw, per-user activity feed. Desktop-only. |
| [**Employer Payroll Test Console**](https://payroll.fractalyze.io) | The mass-payout console (testnet tool, access-gated): deposit public kKRW into the pool, generate a 255-recipient worksheet, and settle it as **one** private disburse, whose proof the GPU prover below returns in seconds when that service is up. |
| **GPU prover service** | The employer-side proving box: three circuits held resident on one GPU, in-process witness workers, ~0.5 s warm proof for the 256-batch. Auth- and origin-gated, so only the employer's own console can reach it. Run on demand rather than kept up: it holds ~25 GB of GPU while resident, and the payroll console is the only surface that needs it — the wallet proves in the browser. |
| **Indexer (arbiter mode)** | Mirrors the on-chain tree, decrypts every authority envelope, serves per-owner `/notes` + `/history` behind signature read-auth, and raises disclosure alarms when a batch's ciphertext disagrees with the chain. |
| **BongtuPool on Maroo Testnet** | The UUPS-proxied pool in [Status](#status): six Groth16 verifiers, the five consumer modules, the IMT, the kKRW escrow, and the enforced 2054-element disclosure on every disburse. |

The two web apps are static; the only server-side pieces are the employer's own prover and the
institution's arbiter indexer — exactly the two parties that hold those roles in the design.

## Status

Live on **Maroo Testnet** (chain 450815), behind a **UUPS proxy** carrying the security-hardened
circuits and enforced four-op auditor disclosure — and, dual-mode from genesis, the five consumer
modules registered inside the deploy broadcast. `initialize` produces the whole enterprise shape
in one call, so the pool serves every entry point from its first block and `currentEpoch()` is 0.

| | address |
|---|---|
| BongtuPool (proxy, B=256) | [`0x3B6238f522a08f08169643cD315e9C44209F1aD6`](https://explorer-testnet.maroo.io/address/0x3B6238f522a08f08169643cD315e9C44209F1aD6) |
| BongtuPool implementation | [`0x607Ab4DbC2C209C170C9E3ceBFEDD1322E8810ea`](https://explorer-testnet.maroo.io/address/0x607Ab4DbC2C209C170C9E3ceBFEDD1322E8810ea) |

Every other address — verifiers, Poseidon, the kKRW token, the consumer modules
([`deploy/modules.450815.json`](deploy/modules.450815.json)) — is in
[`deploy/addresses.450815.json`](deploy/addresses.450815.json), which is the source of truth; take
them from it **by field name** rather than copying one that looks familiar. The retired Base
Sepolia stack stays recorded in [`deploy/addresses.84532.json`](deploy/addresses.84532.json). The
pool implementation, the proxy and `DepositVerifier` are source-verified on the Blockscout
explorer; the remaining contracts are bytecode-only (Poseidon has no Solidity source at all) —
audit them against this repo at the deploying commit.

Verified on-chain through the proxy: `B()==256`, `disburseCiphertextLen==2054` (disclosure enforced),
a real envelope-carrying `deposit`. Measured: warm 256-disburse GPU proof **~0.47s** (2.80M
constraints). Per-op gas and proof times: [`docs/performance.md`](docs/performance.md).

## System map

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│ treasury-web (browser)      │        │ payroll-web (employer)      │
│ MetaMask → bjj key          │        │ recipient list (≤256),      │
│ snarkjs proves a tx         │        │ builds a /prove request     │
└──────────────┬──────────────┘        └──────────────┬──────────────┘
               │                                      │ POST /prove
               │                                      ▼
               │                       ┌─────────────────────────────┐
               │                       │ prover/ (employer GPU box)  │
               │                       │ disburse256 zkey resident   │
               │                       └──────────────┬──────────────┘
               │ tx (a,b,c,pub)                       │ Groth16 calldata
               ▼                                      ▼
┌───────────────────────────────────────────────────────────────────┐
│ BongtuPool (L2):  6 verifiers + IMT + kKRW escrow                 │
└─────────────────────────────────┬─────────────────────────────────┘
                                  │ events: ciphertext, roots, disclosureHash
                                  ▼
┌───────────────────────────────────────────────────────────────────┐
│ indexer (arbiter key):  mirrors the tree, decrypts envelopes to   │
│ per-owner /notes + /history, raises disclosure alarms             │
└───────────────────────────────────────────────────────────────────┘
```

## Layout

npm workspaces monorepo: workspace packages export **raw `src/*.ts`** (no build step) as `@bongtu/*`.
Four kinds of directory, split by what runs the code: `apps/` and `packages/` are the npm world
divided by role (apps are the things you run, packages are the things they import); `chains/` holds
the per-chain consensus islands; `circuits/` and `prover/` are the shared toolchain islands, each
owned by a non-npm toolchain (circom, Python); `deploy/` is the one-shot operations hand — nothing
imports it, it acts on a chain. Each has its own README.

- [`circuits/`](circuits/README.md): the circom circuits (transfer, disburse, withdraw, deposit) + their fixtures, build pipeline and soundness gates
- [`chains/evm/`](chains/evm/README.md): Foundry `BongtuPool` + verifiers
- [`chains/solana/`](chains/solana/README.md): the Solana rail program island (mollusk gates, conformance fixtures)
- [`packages/core/`](packages/core/README.md): `@bongtu/core`: IMT, Poseidon, keys, note crypto, proving wire types
- `packages/client/`: `@bongtu/client`: the browser-side engine both web apps drive — connection, key
  derivation/lock, deposit and spend flows, indexer reads
- `packages/ui/`: `@bongtu/ui`: shared error-surface components (toast host, banner)
- [`prover/`](prover/README.md): GPU prover service — three circuits resident, in-process witness workers
- [`apps/indexer/`](apps/indexer/README.md): event ingest, tree mirror, `/notes` + disclosure alarms (arbiter mode)
- [`apps/payroll-web/`](apps/payroll-web/README.md): the employer pay console — MetaMask login, one worksheet, batch disburse
- [`apps/treasury-web/`](apps/treasury-web/README.md): the institution self-custody wallet, in-browser proving
- [`apps/wallet-web/`](apps/wallet-web/README.md): the consumer self-scan wallet, no-auditor P2P ops (tokenless, in-browser proving)
- [`deploy/`](deploy/README.md): forge scripts, live-chain drivers, anvil gates — recorded addresses at the top
- [`docs/`](docs/): reference docs, one file per topic (index below)
- [`.dev/`](.dev/README.md): working docs: milestone trackers and decision records

## Run

```sh
npm install                               # root: node_modules + @bongtu/* symlinks
npx tsc --noEmit -p tsconfig.json         # type-check the whole tree
```

How to build, test, and run each component lives in its own README:

- **Core library**: [`packages/core/README.md`](packages/core/README.md)
- **Contracts** (forge test, gas report): [`chains/evm/README.md`](chains/evm/README.md)
- **Circuits** (prove_all, soundness gates): [`circuits/README.md`](circuits/README.md)
- **Indexer** (local + live chain, Postgres, docker compose): [`apps/indexer/README.md`](apps/indexer/README.md)
- **Institution wallet** (`apps/treasury-web`: dev server, in-browser proving): [`apps/treasury-web/README.md`](apps/treasury-web/README.md)
- **Consumer wallet** (self-scan, tokenless): [`apps/wallet-web/README.md`](apps/wallet-web/README.md)
- **Payroll console**: [`apps/payroll-web/README.md`](apps/payroll-web/README.md)
- **GPU prover service**: [`prover/README.md`](prover/README.md)
- **Deploy + e2e** (local anvil, live-chain runbook): [`deploy/README.md`](deploy/README.md)

Copy `.env.example` → `.env` (gitignored) for a funded deployer key. Toolchain paths are in
[`docs/toolchain.md`](docs/toolchain.md).

## Docs

System guarantees and inter-component contracts live in [`docs/`](docs/), one file per topic:

- [Protocol](docs/protocol.md): notes, commitments, nullifiers, the single-frontier IMT, batch attach, envelope layouts, the disclosure chain.
- [Circuits](docs/circuits.md): each circuit's exact public surface, the soundness belts, include (`-l`) resolution.
- [Contracts](docs/contracts.md): `BongtuPool`'s duties — proof binding, nullifier spend, enforced disclosure, events, arbiter epochs, the UUPS proxy and verifier wiring.
- [Deployment](docs/deployment.md): the live deployment record, chain facts, the one-shot deploy, the UUPS upgrade path, the arbiter-key-at-deploy coupling.
- [Indexer](docs/indexer.md): the mirror invariant, single-transaction persist and gap-only resume, the HTTP API and its read-auth, the arbiter-mode trust boundary.
- [Wallet](docs/wallet.md): the two wallets on one engine — the shared core (keys, lock, in-browser proving, spend chains), the enterprise wallet, the consumer wallet.
- [Relayer](docs/relayer.md): the gas-sponsoring withdraw submitter and why a proof-bound recipient makes third-party submission safe.
- [Portal](docs/portal.md): stealth deposits — a plain transfer from any wallet becomes a shielded note via CREATE2 destinations and the sweep bot.
- [Consumer family](docs/consumer.md): the no-auditor op family — op-module core, the five consumer circuits, self-scan discovery, deploy profiles, op-level audit semantics.
- [Error surfaces](docs/errors.md): the consequence-class taxonomy and its surfaces (toast = event, banner = state), the money-state line, the no-telemetry stance.
- [Security model](docs/security-model.md): who sees what, the enforced-auditor-disclosure invariant, the zero-commitment guard, residual gaps and testnet caveats.
- [Performance](docs/performance.md): measured gas per operation, proof times, and where the gas goes.
- [Toolchain](docs/toolchain.md): the exact circom/snarkjs/ptau/forge invocations and paths.
- [Zeto derivation](docs/zeto-derivation.md): the Zeto flavor bongtu derives from, per-file provenance, the deliberate modifications, the SMT→IMT soundness debt.

How to run each piece is owned by its own README:

- [Deploy](deploy/README.md): the reusable B=256 stack deploy — env config, local anvil gate, live-chain runbook.
- [Prover service](prover/README.md): the resident-GPU proving service — wire contract, boot lifecycle, ops invariants (one instance per GPU), env knobs.
- [Third-party notices](THIRD_PARTY_NOTICES.md): dependency licenses, GPL isolation for build tools, the wallet's deliberate in-browser snarkjs (GPL) shipment.
- Folder READMEs (layout, run/test commands, API surface):
  [`packages/core`](packages/core/README.md) · [`apps/indexer`](apps/indexer/README.md) ·
  [`circuits`](circuits/README.md) · [`contracts`](chains/evm/README.md) ·
  [`apps/payroll-web`](apps/payroll-web/README.md) · [`apps/treasury-web`](apps/treasury-web/README.md) ·
  [`apps/wallet-web`](apps/wallet-web/README.md).

Milestone trackers and decision records (applied/deferred/rejected lists, layout and CI rationale) live in
[`.dev/`](.dev/README.md): agent-facing working docs, kept out of `docs/`.

## Notes

Testnet PoC: single-party trusted setup, a demo arbiter key, and a mock kKRW token. Mainnet requires a
phase-2 MPC ceremony and a real authority key (see [`docs/security-model.md`](docs/security-model.md)).

## Contributing

- **Merging**: squash-and-merge by default; rebase-merge when a PR's commits
  are each independently meaningful. Never a merge commit — main stays linear.
- **PRs**: written in English, structured for a human skim — a short summary,
  the review points that deserve scrutiny, related issues. Long-lived detail
  belongs in the issue or the commit body, not the PR description.

## License & credits

Licensed under the **Apache License, Version 2.0**; see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

bongtu is built on **[Zeto](https://github.com/hyperledger-labs/zeto)** (Apache-2.0, © 2024 Kaleido, Inc.):
portions of the circom circuits and the on-chain/SDK design are derived from Zeto and modified (each derived
file keeps its Apache header + Kaleido copyright and notes the change). The full dependency and license
breakdown (including how GPL build tools like circom and circomlib are kept external, and where the wallet
deliberately ships snarkjs (GPL) for in-browser proving) is in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
