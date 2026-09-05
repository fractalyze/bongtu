# @bongtu/core

The TypeScript crypto oracle and shared wire types for the whole bongtu stack. Every
commitment, nullifier, Merkle root, and Poseidon-sponge ciphertext in the system is
defined once here, byte-identical to what the circom circuits prove and the on-chain
`BongtuPool` computes: the contract's Foundry differential test pins its IMT against
this package's `ImtTree`, and the circuit fixture generators build their witnesses from
these primitives. Design rationale and security invariants live in
[`.dev/spec-decisions.md`](../../.dev/spec-decisions.md) (§5.1 IMT, §6 keys/encryption, §6b indexer API) —
this README covers only what the package contains and how to run it.

## Modules

Raw-source package with an explicit exports map (subpath → source file), no build
step — consumers import `@bongtu/core/<module>` and tsc (NodeNext), tsx, and Vite all
resolve the same `.ts` source. The map is the one routing table: source files live in
theme folders (`crypto/`, `notes/`, `chain/`, `wire/`) but the import subpaths below
are the stable public names.

| module | owns |
|---|---|
| `imt` | `ImtTree` — the unified single-frontier IMT reference (single-leaf `appendLeaf` + B-leaf `attachSubtree` sharing one frontier), `merklePath`, `computeSubtreeRoot`, and `foldToRoot(leaf, siblings, leafIndex)` |
| `poseidon` | Poseidon-v1 over BN254 (`poseidon2` / `poseidonN`, circomlib-compatible via `poseidon-lite`), `FIELD_PRIME` |
| `babyjub` | pure-JS BabyJubJub group law + scalar multiplication — the one EC op witness building needs, with no curve dependency |
| `note` | note machinery: `commitment`, `nullifier`, `deriveKeypair`, `ecdhSharedSecret`, `poseidonEncrypt` / `poseidonDecrypt` (Poseidon-sponge symmetric), `assertDistinctOwnerPubkeys` (the two-time-pad guard) |
| `consumer` | consumer (no-auditor) note-layer crypto (OPMOD §3): per-output hybrid receiver keys (bjj ECDH view half + ML-KEM-768 encaps), `viewTag` derivation, and the frozen domain-tag literals the five consumer circuits mirror byte-equal |
| `eddsa` | bjj EdDSA-Poseidon sign/verify for the indexer `/notes` read-auth: `notesAuthMessage`, `signNotesAuth`, `verifyNotesAuth`, `packSignature` / `parseSignature` |
| `stealth` | stealth-address derivation for pool-edge payments — dual-curve DKSAP (`stealthKeysFromScalars`, sender `deriveStealthAddress`, view-key `scanStealthAnnouncement`, `recoverStealthKey`, `randomEphemeralScalar`): BabyJubJub ECDH view half + secp256k1 one-time spend key, pinned by a committed determinism vector |
| `pubkey` | compressed bjj pubkey codec (`packPubkey` / `unpackPubkey`) — the 32-byte note-owner identifier on every wire |
| `envelope` | the authority (non-repudiation) envelope codec — per-op plaintext layouts as inverse `buildAuthorityPlaintext` / `parseEnvelope`, `envelopePlaintextLen` / `authorityCiphertextLen`, and the `disclosureChain` Poseidon(2) fold; the disburse layout + fold are byte-pinned to the committed disburse256 proof's publics by `test/envelope.test.ts`; circuit parity for the other three ops is held by the hand-decoded `circuits/gates/auditor_decrypt_check.ts` gate |
| `kem` | hybrid (ECDH ‖ ML-KEM-768) authority-envelope key derivation: the LE-uint128 shared-secret limb packing, `hybridKey` / `kemBinding` folds, frozen tag literals mirrored by the four enterprise circuits |
| `proving` | the shared proving wire types: `ProvingRequest` (a complete, already-resolved circom witness input + circuit tag), `Calldata` (`{a,b,c,pub}`), the per-circuit input shapes, and `toWire` (deep bigint → decimal-string conversion for JSON) |
| `indexerApi` | the spec-normative indexer read-API wire shapes (`FeedEvent`, `OwnerNote`, `Head`, `PathResult`, …), the typed fetch layer, the `/names` directory (`resolveName`, `registerName`, v2 registration), and the `IndexerClient` class binding a URL once with owner-scoped read capabilities — the import home for every indexer consumer since the client-side barrel was removed (issue #15) |
| `errors` | the headless error-surface standard: the AppError consequence-class taxonomy plus the three shared boundary classifiers (indexer reads, chain submissions, in-browser proving) returning structured verdicts each app words itself |
| `network` | the ONE home for the live pool's deployment-coupled chain facts (chain id, gas pin, pool/module/token addresses, `CONSUMER_MODULES`), mirrored field-for-field from `deploy/addresses.450815.json` by a record-equality test |
| `solana` | the Solana rail's deployment-coupled facts (program id, PDA seeds, account layouts and offsets, genesis arbiter epoch, proof/KEM sizes, the base58 codec, the BE/LE encoding rule) — every mirrored constant pinned against the Rust program sources, read as text, by `test/solana.test.ts` |
| `solanaOps` | the per-op public-signal layout table for all nine Solana ops (discriminator, publics count, named field map, derived carried composition and enabled spec, family tags/flags, wire lengths) — reconciled against the Rust op consts and the committed conformance fixtures by the same test |
| `extern` | node-only `createRequire` loader for the deliberately repo-external heavy deps (snarkjs, circomlibjs) via `BONGTU_NODE_MODULES` — never import it from browser code |

## Who consumes it

- `apps/indexer` — `ImtTree` for the mirror, `envelope` for the arbiter ledger's
  decrypt + the disclosure chain, `indexerApi` for the route response types.
- `apps/payroll-web` / `apps/treasury-web` — commitments/ciphertext, `envelope` for the
  disburse assembly + auditor ledger (admin), `proving` request assembly, the
  `indexerApi` client, `pubkey` + `eddsa` for the signed `/notes` read.
- `circuits/` generators and `chains/evm/test/fixtures/` generators — witness inputs and
  the differential/real-proof oracles.
- `deploy/` — the M0 e2e orchestrator and the live 256-disburse runner.
- `prover/` — mirrors `proving.ts` as `prover_service/schema.py` (kept in sync by hand;
  the TS side is the source of truth).

## Installation

Installed and linked by the workspace root — run `npm install` at the repo root (see the
root [`README.md`](../../README.md) Run block). Runtime dependencies are `poseidon-lite` (MIT)
and the audited `@noble` suite (`hashes`, `curves`, `post-quantum`; MIT).

## Usage

```ts
import { ImtTree, foldToRoot } from "@bongtu/core/imt";
import { commitment, nullifier, deriveKeypair } from "@bongtu/core/note";

const key = deriveKeypair(12345n);              // bjj keypair from a scalar
const c = commitment(100n, 7n, key.publicKey);  // poseidon4([value, salt, pubX, pubY])
const nf = nullifier(100n, 7n, key.formattedPrivateKey);

const tree = new ImtTree(32, 256);              // height 32, batch B=256 (pool params)
tree.appendLeaf(c);
const path = tree.merklePath(0);
foldToRoot(c, path.siblings, 0) === tree.getRoot(); // true
```

`extern` is the one node-only module: it loads snarkjs/circomlibjs at runtime
from an external `node_modules` (env `BONGTU_NODE_MODULES` — the repo deliberately
ships no local install of them; see the repo [`CLAUDE.md`](../../CLAUDE.md) and
[`docs/toolchain.md`](../../docs/toolchain.md)).

## Testing

```sh
npm test              # 147 tests (tsx + node --test over test/*.test.ts)
npm run typecheck     # tsc --noEmit
```

The cross-system checks that make this package an oracle run elsewhere: the Foundry
differential test in [`chains/evm/`](../../chains/evm/README.md) (contract root ==
`ImtTree` root at every insert) and the CPU prove pipeline in
[`circuits/`](../../circuits/README.md) (witnesses built from these primitives satisfy
the real circuits).

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE).
