# bongtu (봉투)

[![ci](https://github.com/fractalyze/bongtu/actions/workflows/ci.yml/badge.svg)](https://github.com/fractalyze/bongtu/actions/workflows/ci.yml)

A private stablecoin transfer layer for institutions, built on
[Zeto](https://github.com/hyperledger-labs/zeto) with **enforced auditor disclosure**. Private
peer-to-peer transfers already exist, but institutions need more than that, and no one has made
**private payments work at scale.** bongtu does: one transaction pays up to **256 recipients**, so a
100,000-person payroll settles in minutes for a few dollars, every amount hidden from the public and
readable by an auditor.

A digital 월급봉투: everyone sees the envelopes handed out, only the recipient sees the amount
inside, and a designated authority can open every envelope. Each is encrypted to a fixed authority
key **inside the ZK proof** (non-repudiation), so a regulator can decrypt sender/receiver/amount for
any transaction while the public chain and other users cannot.

## The problem

Stablecoins settle **tens of trillions of dollars a year**, more raw volume than PayPal and on the
order of Visa ([a16z](https://a16zcrypto.com/posts/article/state-of-crypto-report-2025/)). For them
to carry everyday money like salaries, vendor payments, and payouts, a few things have to hold at
once: no one wants their income or spending public, and paying many people has to stay fast and
cheap. A public chain gives neither. It exposes *"individual salaries, bonus structures, and
corporate treasury balances to public view,"* and existing private systems can't do a large payout
without splitting it into hundreds of transactions.

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
level 8 (an **O(log 256)** operation) instead of appending 256 leaves one at a time, which is O(256)
and would not fit in a block. It pads the batch to a fixed 256 with no per-leaf event (so the
real recipient count stays hidden) and publishes all 256 ciphertexts on-chain for the auditor,
bound by one aggregated disclosure hash the proof commits to.

One such batch, measured live against the same circuits and the same hybrid ML-KEM envelope:
**3,905,519 L2 gas** — **15,256 per recipient**. That measurement was taken on the project's
previous chain and has not been re-run on Base Sepolia; it carries over because the move changed no
executable line in any operation path, only the initializer
([`docs/performance.md`](docs/performance.md) shows the check). The other four operations *have*
been re-measured on Base and are in that file.

A **100,000-person payroll** is 391 of those batches, priced at the chain's own 0.006 gwei quote —
not at the higher gas price our deploy scripts pin for themselves:

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

Every surface below is built. The wallet path has run end to end against the pool in
[Status](#status) — deposits, a `transfer10x2` merge and a `transfer10x2` payment all landed on Base
Sepolia and the arbiter indexer surfaced the resulting notes. The 256-recipient disburse has run end
to end, but on the previous deployment; it has not been re-run here:

| surface | what it is |
|---|---|
| [**Bongtu Wallet**](https://bongtu.fractalyze.io) | Self-custody private wallet: spending key derived from a MetaMask signature, proofs generated in the browser, private balance / send / withdraw, per-user activity feed. Desktop-only. |
| [**Employer Payroll Test Console**](https://payroll.fractalyze.io) | The mass-payout console (testnet tool, access-gated): deposit public kKRW into the pool, generate a 255-recipient worksheet, and settle it as **one** private disburse, proof served by the GPU prover in seconds. |
| **GPU prover service** | The employer-side proving box: three circuits resident on one GPU, in-process witness workers, ~0.5 s warm proof for the 256-batch. Auth- and origin-gated; only the employer's own console reaches it. |
| **Indexer (arbiter mode)** | Mirrors the on-chain tree, decrypts every authority envelope, serves per-owner `/notes` + `/history` behind signature read-auth, and raises disclosure alarms when a batch's ciphertext disagrees with the chain. |
| **BongtuPool on Base Sepolia** | The UUPS-proxied pool in [Status](#status): six Groth16 verifiers, the IMT, the kKRW escrow, and the enforced 2054-element disclosure on every disburse. |

The two web apps are static; the only server-side pieces are the employer's own prover and the
institution's arbiter indexer — exactly the two parties that hold those roles in the design.

## Status

Live on **Base Sepolia** (chain 84532), behind a **UUPS proxy** carrying the security-hardened
circuits and enforced four-op auditor disclosure. `initialize` produces that whole shape in one
call, so the pool serves every entry point from its first block and `currentEpoch()` is 0.

| | address |
|---|---|
| BongtuPool (proxy, B=256) | [`0x2a72fea8e97fF79069B3D0165A5DB1Fef7F9322C`](https://sepolia.basescan.org/address/0x2a72fea8e97fF79069B3D0165A5DB1Fef7F9322C) |
| BongtuPool implementation | [`0x960BDc691bB5F6BAfa45Ee9DD188BB4B925Bcc82`](https://sepolia.basescan.org/address/0x960BDc691bB5F6BAfa45Ee9DD188BB4B925Bcc82) |

Every other address — verifiers, Poseidon, the kKRW token — is in
[`deploy/addresses.84532.json`](deploy/addresses.84532.json), which is the source of truth; take
them from it **by field name** rather than copying one that looks familiar. The contracts are not
source-verified on the explorer; audit them against this repo at the deploying commit.

Verified on-chain through the proxy: `B()==256`, `disburseCiphertextLen==2054` (disclosure enforced),
a real envelope-carrying `deposit`. Measured: warm 256-disburse GPU proof **~0.47s** (2.80M
constraints). Per-op gas and proof times: [`docs/performance.md`](docs/performance.md).

## System map

```
┌─────────────────────────────┐        ┌─────────────────────────────┐
│ wallet-web (browser)        │        │ payroll-web (employer)      │
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
Four kinds of directory, split by what runs the code. `apps/` and `packages/` are the npm world
divided by role — apps are the things you run, packages are the things they import. `contracts/`,
`circuits/` and `prover/` are toolchain islands, each owned by a non-npm toolchain (Foundry, circom,
Python). `deploy/` is the one-shot operations hand: nothing imports it, it acts on a chain.
Each has its own README.

- [`circuits/`](circuits/README.md): the circom circuits (transfer, disburse, withdraw, deposit) + their fixtures, build pipeline and soundness gates
- [`contracts/`](contracts/README.md): Foundry `BongtuPool` + verifiers
- [`packages/core/`](packages/core/README.md): `@bongtu/core`: IMT, Poseidon, keys, note crypto, proving wire types
- `packages/client/`: `@bongtu/client`: the browser-side engine both web apps drive — connection, key
  derivation/lock, deposit and spend flows, indexer reads
- `packages/ui/`: `@bongtu/ui`: shared error-surface components (toast host, banner)
- [`prover/`](prover/README.md): GPU prover service — three circuits resident, in-process witness workers
- [`apps/indexer/`](apps/indexer/README.md): event ingest, tree mirror, `/notes` + disclosure alarms (arbiter mode)
- [`apps/payroll-web/`](apps/payroll-web/README.md): the employer pay console — MetaMask login, one worksheet, batch disburse
- [`apps/wallet-web/`](apps/wallet-web/README.md): self-custody wallet, in-browser proving
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
- **Contracts** (forge test, gas report): [`contracts/README.md`](contracts/README.md)
- **Circuits** (prove_all, soundness gates): [`circuits/README.md`](circuits/README.md)
- **Indexer** (local + live chain, Postgres, docker compose): [`apps/indexer/README.md`](apps/indexer/README.md)
- **Wallet** (dev server, in-browser proving): [`apps/wallet-web/README.md`](apps/wallet-web/README.md)
- **Payroll console**: [`apps/payroll-web/README.md`](apps/payroll-web/README.md)
- **GPU prover service**: [`prover/README.md`](prover/README.md)
- **Deploy + e2e** (local anvil, live-chain runbook): [`deploy/README.md`](deploy/README.md)

Copy `.env.example` → `.env` (gitignored) for a funded deployer key. Toolchain paths are in
[`docs/toolchain.md`](docs/toolchain.md).

## Docs

System guarantees and inter-component contracts live in [`docs/`](docs/), one file per topic:

- [Protocol](docs/protocol.md): notes, commitments, nullifiers, the single-frontier IMT, batch attach,
  authority-envelope layouts and the disclosure chain.
- [Circuits](docs/circuits.md): the four circuits, their exact public surfaces, the soundness belts, and how
  `-l` resolves the vendored and upstream includes.
- [Contracts](docs/contracts.md): `BongtuPool`'s duties: proof binding, nullifier spend, enforced disclosure,
  events, arbiter epochs, the UUPS proxy and verifier wiring.
- [Deployment](docs/deployment.md): the live deployment record, chain facts, the one-shot deploy and the
  UUPS upgrade path, and the arbiter-key-at-deploy coupling.
- [Indexer](docs/indexer.md): the mirror invariant, single-transaction persist and gap-only resume, the HTTP
  API with its read-auth, and the arbiter-mode trust boundary.
- [Wallet](docs/wallet.md): key derivation from a MetaMask signature, in-browser proving and the stale-zkey
  hazard, the deposit/faucet shape, and the indexer dependency.
- [Error surfaces](docs/errors.md): the five consequence classes and their surfaces (toast = event,
  banner = state), the money-state line, and the no-telemetry stance.
- [Security model](docs/security-model.md): who sees what, the enforced-auditor-disclosure invariant, the
  zero-commitment guard, and the residual gaps and testnet caveats.
- [Performance](docs/performance.md): measured gas per operation, the live 256-disburse run, proof times,
  and where the gas actually goes.
- [Toolchain](docs/toolchain.md): the exact circom/snarkjs/ptau/forge invocations and paths that build and
  prove everything.
- [Zeto derivation](docs/zeto-derivation.md): which Zeto flavor bongtu uses, per-file circuit provenance, the
  deliberate modifications, and the SMT→IMT soundness debt.

How to run each piece is owned by its own README:

- [Deploy](deploy/README.md): the reusable B=256 stack deploy: env config, local anvil gate, live-chain runbook.
- [Prover service](prover/README.md): the resident-GPU proving service: wire contract, boot lifecycle, ops
  invariants (one instance per GPU), env knobs.
- [Third-party notices](THIRD_PARTY_NOTICES.md): dependency licenses, GPL isolation for build tools, and the
  wallet's deliberate in-browser snarkjs (GPL) shipment.
- Folder READMEs: each folder's own layout, run/test commands, and API surface:
  [`packages/core`](packages/core/README.md) · [`apps/indexer`](apps/indexer/README.md) ·
  [`circuits`](circuits/README.md) · [`contracts`](contracts/README.md) ·
  [`apps/payroll-web`](apps/payroll-web/README.md) · [`apps/wallet-web`](apps/wallet-web/README.md).

Milestone trackers and decision records (applied/deferred/rejected lists, layout and CI rationale) live in
[`.dev/`](.dev/README.md): agent-facing working docs, kept out of `docs/`.

## Notes

Testnet PoC: single-party trusted setup, a demo arbiter key, and a mock kKRW token. Mainnet requires a
phase-2 MPC ceremony and a real authority key (see [`docs/security-model.md`](docs/security-model.md)).

## License & credits

Licensed under the **Apache License, Version 2.0**; see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

bongtu is built on **[Zeto](https://github.com/hyperledger-labs/zeto)** (Apache-2.0, © 2024 Kaleido, Inc.):
portions of the circom circuits and the on-chain/SDK design are derived from Zeto and modified (each derived
file keeps its Apache header + Kaleido copyright and notes the change). The full dependency and license
breakdown (including how GPL build tools like circom and circomlib are kept external, and where the wallet
deliberately ships snarkjs (GPL) for in-browser proving) is in [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
