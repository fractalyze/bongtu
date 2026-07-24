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

Live on **GIWA Sepolia** (chain 91342), behind a **UUPS proxy** carrying the security-hardened circuits and
enforced four-op auditor disclosure.

| | address |
|---|---|
| BongtuPool (proxy, B=256) | [`0x93365980784ef504613EF5822ce1289CF858Fc10`](https://sepolia-explorer.giwa.io/address/0x93365980784ef504613EF5822ce1289CF858Fc10) |
| BongtuPool impl | [`0x459f80A457f11328eBd67aeBFa9F90D05c58b27f`](https://sepolia-explorer.giwa.io/address/0x459f80A457f11328eBd67aeBFa9F90D05c58b27f) |

Verified on-chain through the proxy: `B()==256`, `disburseCiphertextLen==2054` (disclosure enforced), a real
envelope-carrying `deposit`. Measured: warm 256-disburse GPU proof **~0.47s** (2.79M constraints); on-chain
256-payout ~3M L2 gas (~11.8k/recipient, under the Karst cap); the L1/blob-DA fee is negligible even with all
ciphertext on-chain. (The headline 256-disburse ran end-to-end on the v1 pool `0x22a2F38a…`; re-demoing it on
this v2 pool needs the 256 proof re-proven against its arbiter key — see `docs/spec.md` §9.)

## Layout

- `circuits/` — circom (transfer 2×2, disburse 1×16 dev / 1×256 prod, withdraw 2×1, deposit; IMT depth-32, Poseidon-v1)
- `contracts/` — Foundry: `BongtuPool` (unified single-frontier IMT + contract-derived enabled + arbiter epochs) + verifiers
- `sdk/` — TS: single-frontier IMT, Poseidon, BabyJubjub keys, note/encrypt, trial-decrypt
- `deploy/` — Foundry deploy script (local anvil + GIWA), the live 256-disburse runner, the M0 cross-circuit e2e
- `indexer/` — event ingest → MirrorTree mirror (root == on-chain root), merkle-path + ciphertext-feed API, disclosure alarms; **arbiter mode** (`AUTHORITY_KEY`) decrypts every envelope to serve `/notes?owner=` + within-batch paths
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
- [Zeto derivation](docs/zeto-derivation.md) — which Zeto flavor bongtu uses, per-file circuit provenance, the
  deliberate modifications, and the SMT→IMT soundness finding (why Unit 0 redeploys).
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
