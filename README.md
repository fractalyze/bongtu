# bongtu (봉투)

An institutional privacy token on **GIWA** (OP Stack L2), built on [Zeto](https://github.com/hyperledger-labs/zeto)
with **enforced auditor disclosure**. A digital 월급봉투: everyone sees envelopes handed out, only the recipient
sees the amount inside, and a designated authority can open every envelope.

Every transfer is encrypted to a fixed authority key **inside the ZK proof** (non-repudiation), so a regulator
can decrypt sender/receiver/amount for any transaction while the public chain and other users cannot. It keeps
Zeto's normal payments (private p2p transfer, deposit, withdraw) and adds the headline no competitor does: a
**single-transaction, 256-recipient private disbursement**, proven off-chain on GPU and verified on-chain in
O(tree height).

## Status

Live on **GIWA Sepolia** (chain 91342). A real 256-recipient private disburse has run end-to-end on the
deployed pool.

| | address / tx |
|---|---|
| BongtuPool (B=256) | [`0x22a2F38a24a2647E430dc28a5154D390F93Ccf7b`](https://sepolia-explorer.giwa.io/address/0x22a2F38a24a2647E430dc28a5154D390F93Ccf7b) |
| 256-recipient disburse | [`0xc97836e0…abc37e`](https://sepolia-explorer.giwa.io/tx/0xc97836e05651756c333fc18bbb4698182f5d5690e41bd103e3e42eb178abc37e) |

Measured: 256-payout ≈ 3.03M L2 gas (11.8k / recipient, under the Karst cap); warm GPU proof ~0.47s; the L1
data fee is ~0.05% of cost even with all 256 ciphertexts on-chain.

## Layout

- `circuits/` — circom (transfer 2×2, disburse 1×16 dev / 1×256 prod, withdraw 2×1, deposit; IMT depth-32, Poseidon-v1)
- `contracts/` — Foundry: `BongtuPool` (unified single-frontier IMT + contract-derived enabled + arbiter epochs) + verifiers
- `sdk/` — TS: single-frontier IMT, Poseidon, BabyJubjub keys, note/encrypt, trial-decrypt
- `deploy/` — Foundry deploy script (local anvil + GIWA), the live 256-disburse runner, the M0 cross-circuit e2e
- `indexer/` — event ingest → SDK-IMT mirror (root == on-chain root), merkle-path + ciphertext-feed API, disclosure alarms
- `docs/` — specification, milestone records, toolchain (see the index below)

## Run

```sh
# sdk (TypeScript oracle: IMT / Poseidon / babyjub / note crypto)
cd sdk && npm install && npm test     # 21 tests (tsx + node --test)

# contracts
cd contracts && forge test            # 27 tests

# circuits (CPU proofs) — generators run through tsx
cd circuits && bash prove_all.sh      # 4× snarkjs OK

# cross-circuit spend cycle on a local anvil (TS orchestrator via tsx)
bash deploy/e2e_m0.sh

# indexer conformance (anvil scenario: ingest, mirror==contract, paths, alarms)
cd indexer && npm test

# deploy the full B=256 stack to a local node (or GIWA via env — see deploy/README.md)
bash deploy/deploy_local.sh

# run the indexer against the live GIWA pool (read-only)
cd indexer && RPC=https://sepolia-rpc.giwa.io npm start
```

The `.ts` scripts under `sdk/`, `deploy/`, `circuits/`, and `contracts/test/fixtures/` run on [`tsx`](https://github.com/privatenumber/tsx)
(ESM / NodeNext, `strict`); `npm install` at the repo root installs the shared TS toolchain. Type-check everything with
`npx tsc --noEmit -p tsconfig.json` (scripts) and `cd sdk && npx tsc --noEmit` (the sdk package).

Copy `.env.example` → `.env` (gitignored) for a funded GIWA deployer key. Toolchain paths are in
[`docs/toolchain.md`](docs/toolchain.md).

## Docs

- [Specification](docs/spec.md) — what bongtu is and why it is shaped this way: locked product decisions,
  circuits/publics, IMT §5.1, indexer API §6b, apps §7, GIWA facts + live addresses §9, risk register §11.
- [Milestone M0](docs/milestone-m0.md) — how the core was proven safe: 4 units, gates, and the two retired
  critical risks (mixed-mode tree spend, enabled-forgery mint).
- [Milestone M1](docs/milestone-m1.md) — how 1×256 GPU disburse + the GIWA deploy landed: gas numbers, the
  O(log B) partial-block fix, deploy pipeline evidence.
- [Toolchain](docs/toolchain.md) — the exact circom/snarkjs/ptau/forge invocations and paths that build and
  prove everything.
- [Deploy](deploy/README.md) — the reusable B=256 stack deploy: env config, local anvil gate, live GIWA runbook.
- [Third-party notices](THIRD_PARTY_NOTICES.md) — dependency licenses and how GPL build tools stay un-bundled.

## Notes

Testnet PoC: single-party trusted setup, a demo arbiter key, and a mock kKRW token — mainnet requires a
phase-2 MPC ceremony and a real authority key (see [`docs/spec.md`](docs/spec.md) §11/§13).

## License & credits

Licensed under the **Apache License, Version 2.0** — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

bongtu is built on **[Zeto](https://github.com/hyperledger-labs/zeto)** (Apache-2.0, © 2024 Kaleido, Inc.):
portions of the circom circuits and the on-chain/SDK design are derived from Zeto and modified (each derived
file keeps its Apache header + Kaleido copyright and notes the change). Full dependency and license breakdown —
including how GPL build tools (circom, snarkjs, circomlib) are kept external and un-bundled — is in
[`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md).
