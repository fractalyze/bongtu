# @bongtu/indexer

The bongtu read-side service: it ingests `BongtuPool` events from an RPC, maintains an
off-chain mirror of the on-chain IMT, and serves the merkle-path / ciphertext-feed /
alarm API that the wallet and admin apps depend on. It is read-only on-chain (opens no
wallet, sends no transactions) and — post-Q4 — a convenience/availability layer, not
trust-critical for funds. The normative API contract and the security model live in
[`docs/spec.md`](../../docs/spec.md) §6b; the wire shapes are owned by
[`@bongtu/sdk/indexerApi`](../../packages/sdk/README.md) and the routes type their
response bodies against them.

## Two modes

- **Public mode** (default, no key): serves only public chain data — feed, roots,
  paths, nullifiers, disclosure alarms. Batch-interior merkle paths are structurally
  unservable (siblings are encrypted to other recipients) and return 422.
- **Arbiter mode** (`AUTHORITY_KEY` set to the arbiter bjj private key): additionally
  decrypts every op's authority envelope into a per-owner note ledger and serves
  `GET /notes?owner=` plus within-batch `/path`. Institution-internal by nature — the
  key is held in memory only, never logged, never returned. See the repo
  [`CLAUDE.md`](../../CLAUDE.md) "Indexer modes" rule.

## Endpoints

| endpoint | returns |
|---|---|
| `GET /head` | `{ root, nextLeafIndex }` — ingested mirror state |
| `GET /events?cursor=&limit=` | the ciphertext feed a wallet trial-decrypts: `[{ seq, txHash, blockNumber, kind, epoch, ecdhPublicKey, encryptionNonce, slices:[{offset, elts, leafIndex}], ciphertext[], disclosure? }]` |
| `GET /path/{leafIndex}` | `{ leafIndex, siblings[], pathIndices[], root }`; 404 out-of-range; **422** for a disburse-batch interior leaf in public mode (served in arbiter mode) |
| `GET /alarms` | one discriminated feed: every non-passing disclosure (`{type:"disclosure"}`, status `mismatch` / `unverifiable` / `withheld`) plus, arbiter mode only, envelope cross-check failures (`{type:"envelope"}`) |
| `GET /nullifiers` | `string[]` — the spent-nullifier set from events (public, key-free) |
| `GET /health` | `{ ok, lastBlock, nextLeafIndex, batchSize, alarms, lastSuccessAt, lastError, lastErrorAt, consecutiveFailures }` — `ok` is false when the tail poll is persistently failing |
| `GET /notes?owner=&ts=&sig=` | **arbiter mode only** (the route does not exist otherwise → 404): one owner's decrypted notes `[{ value, salt, leafIndex, commitment, txHash, spent }]` |

`/notes` auth is enforced: `owner` is the compressed bjj pubkey
(`@bongtu/sdk/pubkey`), `sig` a bjj EdDSA-Poseidon signature over
`Poseidon(ownerPub.x, ownerPub.y, ts)` checked against the queried key
(`@bongtu/sdk/eddsa`), and `|now − ts| ≤ 300s` bounds replay. Malformed owner → 400;
wrong key or expired ts → 401.

Routing is a plain ordered table (`src/api/router.ts`): each route is a pure function
of the indexer + parsed params returning `{status, body}`; arbiter mode composes the
`/notes` route in at build time, so a public indexer cannot serve it even by request
path.

## Mirror invariant

`MirrorTree` (`src/tree.ts`) wraps the SDK `ImtTree` — the same class the contract's
Foundry differential test pins against — and applies the two low-level tree events
(`Appended`, batch attach), each of which carries the resulting on-chain root, so
**the mirror is asserted against the contract per insert**, not just at head. All
endpoints serve this ingested state, which keeps the API mutually consistent and
available even when the RPC is not. For every `disburse` it also recomputes the
Poseidon chain over the emitted ciphertext and compares it to the on-chain
`disclosureHash` (`src/disclosure.ts`) — any failure surfaces on `/alarms`.

## Run

```sh
npm start                                          # defaults: local anvil RPC, port 8600
RPC=https://sepolia-rpc.giwa.io npm start          # against the live GIWA pool (read-only)
```

Env knobs (`src/index.ts`):

| env | default | meaning |
|---|---|---|
| `RPC` / `GIWA_RPC` / `E2E_RPC` | anvil `127.0.0.1:8545` | RPC endpoint |
| `POOL` | from `deploy/addresses.<CHAIN_ID>.json` | pool address |
| `CHAIN_ID` | `91342` | chain id for the addresses file |
| `START_BLOCK` | `0` | first block to replay |
| `PORT` | `8600` | HTTP port |
| `POLL_MS` | `5000` | incremental re-ingest interval (`0` = off) |
| `AUTHORITY_KEY` | unset | arbiter bjj private key → arbiter mode |

Workspace install and shared tooling: root [`README.md`](../../README.md). Loading the
pool ABI and ethers goes through the external-`node_modules` seam (`BONGTU_NODE_MODULES`,
see [`CLAUDE.md`](../../CLAUDE.md)) and needs a `forge build` artifact for the pool ABI.

## Testing

```sh
npm run test:unit    # anvil-free units: tree + disclosure + ingest (fast inner loop)
npm run typecheck    # tsc --noEmit
npm test             # the full conformance gate (bash test/run.sh) — heavy
```

The conformance gate starts its own anvil on port **8552** (override
`INDEXER_E2E_PORT` if that port is taken), deploys a fresh B=16 pool, drives the full
scenario (deposit → disburse → transfer → withdraw → tampered disburses), and asserts
mirror==contract at every step, path folding, trial-decrypt, the alarm classes, and
the arbiter-mode ledger + `/notes` + within-batch `/path`. It needs the CPU proving
artifacts under `circuits/out/` (`cd circuits && bash prove_all.sh` first) and runs as
the `indexer-conformance` job in CI — treat it as a final gate, not a per-iteration
loop (repo `CLAUDE.md` "Heavy gates").

## Layout

```
src/
  index.ts        runnable service: env → ingest → serve (+ tail polling)
  chain.ts        config resolution + RPC/ABI plumbing
  ingest.ts       Indexer: event ingest, correlation, poll/retry state
  tree.ts         MirrorTree: ImtTree mirror + per-leaf records + batch subtrees + path builder
  store.ts        ingested events / alarms / nullifiers store
  disclosure.ts   disclosureHash verify + alarm classification (chain fold from @bongtu/sdk/envelope)
  ledger.ts       arbiter-mode per-owner note ledger (spent from envelopes alone; decode via @bongtu/sdk/envelope)
  api/            router + one file per route (see Endpoints above)
test/             unit tests + the anvil conformance scenario (run.sh)
```

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE).
