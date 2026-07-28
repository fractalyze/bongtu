# bongtu (봉투)

[![ci](https://github.com/fractalyze/bongtu/actions/workflows/ci.yml/badge.svg)](https://github.com/fractalyze/bongtu/actions/workflows/ci.yml)

A private stablecoin transfer layer for institutions, built on
[Zeto](https://github.com/hyperledger-labs/zeto) with **enforced auditor disclosure**. Private
peer-to-peer transfers already exist, but institutions need more than that, and no one has made
**private payments work at scale.** bongtu does: one transaction pays up to **256 recipients**, so a
100,000-person payroll settles in minutes for a few dollars, every amount hidden from the public and
readable by an auditor. And scale *is* the privacy here: split a mass payout into thousands of
separate transfers and their timing re-links the sender, undoing the privacy of each.

A digital 월급봉투: everyone sees the envelopes handed out, only the recipient sees the amount
inside, and a designated authority can open every envelope. Each is encrypted to a fixed authority
key **inside the ZK proof** (non-repudiation), so a regulator can decrypt sender/receiver/amount for
any transaction while the public chain and other users cannot.

## The problem

Stablecoins settle **tens of trillions of dollars a year**, more raw volume than PayPal and on the
order of Visa ([a16z](https://a16zcrypto.com/posts/article/state-of-crypto-report-2025/)). Yet
**fewer than 1% of businesses use them for payroll**
([Toku](https://www.toku.com/resources/aleo-toku-and-paxos-labs-launch-first-private-stablecoin-payroll-solution-removing-the-final-barrier-to-enterprise-stablecoin-adoption)),
against a **$55 trillion** global payroll market. The reason is not speed or cost. A public chain
exposes *"individual salaries, bonus structures, and corporate treasury balances to public view."*

When you use a bank, you take four things for granted:

|   | You expect… | Public stablecoin | **bongtu** |
|---|---|---|---|
| 1 | your balance & history are yours alone | ❌ world-readable | ✅ |
| 2 | outsiders can't see how much you send | ❌ | ✅ |
| 3 | outsiders can't see who you send to | ❌ | ✅ |
| 4 | but a regulator can still audit you | "✅" (all public) | ✅ cryptographically enforced |

A public stablecoin fails the first three. Privacy tools (mixers like Tornado) fix those but lack
built-in auditability, which is why [Tornado Cash was
sanctioned](https://home.treasury.gov/news/press-releases/jy0916). These four are the basic
requirements; bongtu meets them **at scale**, across a payroll-sized payout in a single transaction.

> Requirement #3 is why *"protect the payroll file"* has become *"protect the payroll graph"*
> ([Toku](https://www.toku.com/resources/payroll-data-privacy)): hiding amounts alone still leaks
> headcount, churn, and payday timing. Requirement #4 is what a16z calls *"the nuclear option:
> involuntary selective de-anonymization"*
> ([a16z](https://a16zcrypto.com/achieving-crypto-privacy-and-regulatory-compliance/)); every other
> private-payments system offers only *voluntary* viewing keys the user must choose to share.

## How the field compares

Verified against each project's source/artifacts, for the exact configuration each ships:

| | **bongtu** | Zeto (non-rep) | Railgun v2 | zkBob | Token-2022 CT |
|---|---|---|---|---|---|
| Private peer-to-peer transfer | ✅ | ✅ | ✅ | ✅ | ⚠️ amounts only |
| **Practical 1-to-N mass payout** | ✅ **256 / tx** | ❌ 10 | ❌ 5¹ | ⚠️ 127 (sunset) | ❌ |
| Hides amounts | ✅ | ✅ | ✅ | ✅ | ✅ |
| Hides sender↔recipient graph | ✅ | ✅ | ✅ | ✅ | ❌ addresses public |
| Hides org headcount / cadence | ✅² | ⚠️ | ⚠️ | ⚠️ count leaks³ | ❌ |
| **Auditor sees without user consent** | ✅ circuit-enforced | ✅ circuit-enforced | ❌ voluntary | ❌ voluntary | ✅ circuit-enforced |
| Per-period (epoch) disclosure | ✅ on-chain rotation | ❌ key fixed at deploy | ❌ | ❌ | ❌ single key |
| Post-quantum (HNDL) protection | ✅ hybrid ML-KEM-768 | ⚠️ PQ-only variant⁴ | ❌ | ❌ | ❌ |
| Per-user note-fetch service | ✅ indexer `/notes` | ❌ scan all | ❌ scan all⁵ | ❌ scan all | n/a |
| Live today | ✅ GIWA testnet | ✅ | ✅ | ❌ **sunset** | ✅ |

¹ Railgun reaches 13 outputs only when spending a single input; from a normal multi-UTXO balance the
ceiling is 5 ([artifacts.json](https://github.com/Railgun-Community/shared-models/blob/main/src/json/artifacts.json)).
² A disburse pads to a fixed 256 with no per-leaf events, so the real recipient count is not
on-chain.
³ zkBob and Railgun hide *who* the recipients are but publish the *count* (zkBob's variable-length
memo carries an item count; Railgun emits one commitment event per output).
⁴ Zeto's PQ variant (Qurrency) is ML-KEM-512 **PQ-only, not hybrid**, drops the auditor role, and
bakes the auditor key into the circuit with no rotation path.
⁵ Railgun's QuickSync is a bulk event feed; the client still trial-decrypts every commitment.

**Three gaps no live system closes, and bongtu closes all three:** (1) audit that is both
protocol-enforced *and* selectively scoped (everyone else's is voluntary and whole-wallet);
(2) any HNDL mitigation on the ciphertext written permanently on-chain (four of four competitors
publish an ephemeral pubkey next to every note); (3) a per-recipient note-discovery service instead
of scanning the whole pool.

## The headline: mass private disbursement

One transaction pays up to **256 recipients**, each with an amount only they and the auditor can
read. Measured on the live GIWA pool: **3,872,403 gas ≈ 15,126 per recipient**
([tx](https://sepolia-explorer.giwa.io/tx/0xe254240a5df042a163073c028399a5fc63cf87434a7e7ebbf5ddfea73c803bd6)).

At that rate **100,000 recipients ≈ 391 transactions ≈ ~1.5 billion gas**, on GIWA (OP-stack L2,
0.005 gwei) roughly **a few minutes and tens of dollars** end to end; GPU proving is ~0.47 s/batch
warm and never the bottleneck. Against Zeto's own published 2,763,071 gas for a **2-recipient**
transfer (~1.38M/recipient), bongtu is **~90× cheaper per recipient**: the gap is the value-keyed
SMT we replaced with an IMT batch-attach and the ciphertext bloat we replaced with an aggregated
disclosure hash. *(The 15,126/recipient figure predates the hybrid ML-KEM envelope, which adds the
KEM ciphertext cost; that batch has not been re-measured live.)*

## Status

Live on **GIWA Sepolia** (chain 91342), behind a **UUPS proxy** carrying the security-hardened circuits and
enforced four-op auditor disclosure.

| | address |
|---|---|
| BongtuPool (proxy, B=256) | [`0x93365980784ef504613EF5822ce1289CF858Fc10`](https://sepolia-explorer.giwa.io/address/0x93365980784ef504613EF5822ce1289CF858Fc10) |
| BongtuPool impl (hybrid PQ epoch 1 + self-send) | [`0x91fb94B656BE4eb86eD0Cdf4f172f620c61d21f7`](https://sepolia-explorer.giwa.io/address/0x91fb94B656BE4eb86eD0Cdf4f172f620c61d21f7) |

Verified on-chain through the proxy: `B()==256`, `disburseCiphertextLen==2054` (disclosure enforced), a real
envelope-carrying `deposit`. Measured: warm 256-disburse GPU proof **~0.47s** (2.80M constraints); the
headline 256-disburse has run end-to-end on this pool (tx `0xe254240a…`, `nextLeafIndex` 4→512) at
3,872,403 L2 gas (15,126 per recipient, far under the Karst cap), plus ~4e-6 ETH of L1 data fee for the
~66 KB ciphertext array. Per-op gas and proof times: [`docs/performance.md`](docs/performance.md).

## System map

```
┌────────────────────────────┐     ┌────────────────────────────┐
│ wallet-web (browser)       │     │ payroll-web (employer)     │
│ MetaMask → bjj key,        │     │ recipient list (≤256),     │
│ snarkjs proves tx          │     │ builds a /prove request    │
└─────────────┬──────────────┘     └──────────────┬─────────────┘
              │                                    │ POST /prove
              │                                    ▼
              │                     ┌────────────────────────────┐
              │                     │ prover/ (employer GPU box) │
              │                     │ disburse256 zkey resident  │
              │                     └──────────────┬─────────────┘
              │ tx (a,b,c,pub)       Groth16 calldata, employer submits
              ▼                                    ▼
┌──────────────────────────────────────────────────────────────┐
│ BongtuPool (GIWA L2):  4 verifiers + IMT + kKRW escrow        │
└───────────────────────────────┬──────────────────────────────┘
                                 │ events: ciphertext, roots, disclosureHash
                                 ▼
┌──────────────────────────────────────────────────────────────┐
│ indexer (arbiter key):  mirrors the tree (root == on-chain),  │
│ decrypts envelopes → per-owner /notes + /history, alarms      │
└──────────────────────────────────────────────────────────────┘
```

## Layout

npm workspaces monorepo: workspace packages export **raw `src/*.ts`** (no build step) as `@bongtu/*`;
`circuits/`, `contracts/`, `prover/`, `deploy/` stay top-level (non-npm toolchains). Each has its own README.

- [`circuits/`](circuits/README.md): the circom circuits (transfer, disburse, withdraw, deposit)
- [`contracts/`](contracts/README.md): Foundry `BongtuPool` + verifiers
- [`packages/core/`](packages/core/README.md): `@bongtu/core`: IMT, Poseidon, keys, note crypto, proving wire types
- [`prover/`](prover/README.md): GPU prover service, holds the disburse256 zkey resident
- [`apps/indexer/`](apps/indexer/README.md): event ingest, tree mirror, `/notes` + disclosure alarms (arbiter mode)
- [`apps/payroll-web/`](apps/payroll-web/README.md): employer + auditor console
- [`apps/wallet-web/`](apps/wallet-web/README.md): self-custody wallet, in-browser proving
- [`deploy/`](deploy/README.md): deploy scripts, the live 256-disburse runner, the e2e gate
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
- **Indexer** (local + live GIWA, Postgres, docker compose): [`apps/indexer/README.md`](apps/indexer/README.md)
- **Wallet** (dev server, in-browser proving): [`apps/wallet-web/README.md`](apps/wallet-web/README.md)
- **Payroll console**: [`apps/payroll-web/README.md`](apps/payroll-web/README.md)
- **GPU prover service**: [`prover/README.md`](prover/README.md)
- **Deploy + e2e** (local anvil, live GIWA runbook): [`deploy/README.md`](deploy/README.md)

Copy `.env.example` → `.env` (gitignored) for a funded GIWA deployer key. Toolchain paths are in
[`docs/toolchain.md`](docs/toolchain.md).

## Docs

System guarantees and inter-component contracts live in [`docs/`](docs/), one file per topic:

- [Protocol](docs/protocol.md): notes, commitments, nullifiers, the single-frontier IMT, batch attach,
  authority-envelope layouts and the disclosure chain.
- [Circuits](docs/circuits.md): the four circuits, their exact public surfaces, the soundness belts, and how
  `-l` resolves the vendored and upstream includes.
- [Contracts](docs/contracts.md): `BongtuPool`'s duties: proof binding, nullifier spend, enforced disclosure,
  events, arbiter epochs, the UUPS proxy and verifier wiring.
- [Deployment](docs/deployment.md): live GIWA Sepolia addresses, chain facts, the deploy scripts, and the
  arbiter-key-at-deploy coupling.
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

- [Deploy](deploy/README.md): the reusable B=256 stack deploy: env config, local anvil gate, live GIWA runbook.
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
