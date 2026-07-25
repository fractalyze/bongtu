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
| `GET /history?owner=&ts=&sig=` | **arbiter mode only** (else 404): one owner's activity feed `[{ kind, counterparty, amount, txHash, blockTimestamp, seq }]`, newest-first. `kind` ∈ `received`/`sent`/`withdraw`/`deposit`; `counterparty` is a compressed pubkey (or null); derived from the same decrypted envelopes as `/notes` — same bjj read-auth |

`/notes` and `/history` share the same enforced read-auth: `owner` is the
compressed bjj pubkey (`@bongtu/sdk/pubkey`), `sig` a bjj EdDSA-Poseidon signature
over `Poseidon(ownerPub.x, ownerPub.y, ts)` checked against the queried key
(`@bongtu/sdk/eddsa`), and `|now − ts| ≤ 300s` bounds replay. Malformed owner → 400;
missing ts/sig → 400; wrong key or expired ts → 401. `buildNotesUrl` /
`buildHistoryUrl` (`@bongtu/sdk/indexerApi`) are the one client-side implementation,
headless-tested against the same verifier the routes use.

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

## Storage backends

The store (`Store`/`StorePort`) and the arbiter note ledger (`NoteLedger`/`LedgerPort`)
are interfaces with **two adapters**, picked at first ingest by `DATABASE_URL`:

- **In-memory** (default, `DATABASE_URL` unset): the original behaviour — everything is
  re-derived from chain on every start. This is what all the unit + conformance gates
  and hosted CI run, and it is unchanged.
- **Postgres** (`DATABASE_URL` set): the derived state (the event feed, nullifier set,
  the tree leaves, the arbiter notes/history/alarms) is persisted to Postgres, and a
  single-row **block cursor** lets a restart **RESUME** ingest from the cursor instead
  of replaying the whole chain. Each poll batch's rows AND the cursor advance in **one
  transaction** (`Indexer.persist`), so a crash can never leave the `leaves` table ahead
  of the cursor — the state a restart reconstructs is always mutually consistent (proved
  by `test/pg_resume.ts`). Leaf writes are a **delta** (only leaves recorded since the
  last flush), not a full re-snapshot. The `MirrorTree` is not stored as nodes — it is
  boot-**reconstructed** from the `leaves` table (`O(n)`); the note ledger is rehydrated
  from the `notes`/`history` tables. Reads are served from the same in-memory read model
  both adapters keep (so the API stays synchronous), with Postgres as the durable cache.

The decrypt/derive step (envelope → notes/spent-marks/alarms/history) is ONE shared pure
function (`deriveOp` in `ledger.ts`) both ledger adapters call — the crypto is never
duplicated; only where rows are recorded/read differs. Schema: [`src/schema.sql`](src/schema.sql)
(idempotent `CREATE TABLE IF NOT EXISTS`, applied on every boot).

## Run

```sh
npm start                                          # defaults: local anvil RPC, port 8600
RPC=https://sepolia-rpc.giwa.io npm start          # against the live GIWA pool (read-only)
DATABASE_URL=postgres://… npm start                # persist + resume (Postgres backend)
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
| `DATABASE_URL` | unset | Postgres connection string → the **Postgres backend** (persist + boot-resume). Unset = **in-memory** (default, unchanged) |

Workspace install and shared tooling: root [`README.md`](../../README.md). Loading the
pool ABI and ethers goes through the external-`node_modules` seam (`BONGTU_NODE_MODULES`,
see [`CLAUDE.md`](../../CLAUDE.md)) and needs a `forge build` artifact for the pool ABI.

## Docker / compose (U-I3)

A 2-service stack — **postgres + indexer** — is defined at the repo root
([`docker-compose.yml`](../../docker-compose.yml)); the prover (GPU) and the static web
apps are deliberately out of scope.

```sh
docker compose up --build                     # postgres (named volume + healthcheck) then
                                              # the indexer, RPC defaulting to a HOST anvil
                                              # on :8545 via host.docker.internal
cp .env.compose.example .env.compose          # edit RPC / POOL / AUTHORITY_KEY / START_BLOCK
docker compose --env-file .env.compose up --build
```

Compose starts postgres first (gated on `pg_isready`), then the indexer, which sets
`DATABASE_URL` at the postgres service, **applies `schema.sql` on boot** (idempotent), and
ingests. The named `pgdata` volume persists across `up`/`down`, so a restart **RESUMES**
from the block cursor. Knobs are interpolated from the shell / `--env-file` with sane
defaults (`.env.compose.example`); leave `POOL` empty to fall back to the baked-in
`deploy/addresses.<CHAIN_ID>.json` (91342 = the live GIWA pool). The indexer serves
`GET /health` on **8600**, and the container's `HEALTHCHECK` reports healthy once
`/health` returns `ok:true`. `AUTHORITY_KEY` flips the container to arbiter mode
(institution-internal — see [`CLAUDE.md`](../../CLAUDE.md)).

The image ([`apps/indexer/Dockerfile`](Dockerfile), context = repo root) is multi-stage:
a builder trims the npm workspace to `packages/sdk` + `apps/indexer` (a lockfile-pinned
`npm ci --workspace …`, no react/vite) and installs ethers into the
`BONGTU_NODE_MODULES` seam; the slim non-root runtime copies the installed tree, the raw
`.ts` source (run via `node --import tsx`), the addresses file, and the **committed pool
ABI** ([`abi/BongtuPool.abi.json`](abi/README.md)) placed at
`contracts/out/BongtuPool.sol/BongtuPool.json` so the image is self-contained (no foundry
in the build) and reproducible. CI builds this image **build-only** (`indexer-image`
job); `docker compose up` and the pg integration test below stay LOCAL gates.

## Testing

```sh
npm run test:unit    # anvil-free units: tree + disclosure + ingest (fast inner loop)
npm run typecheck    # tsc --noEmit
npm test             # the full conformance gate (bash test/run.sh) — heavy, IN-MEMORY
npm run test:pg      # the Postgres two-adapter gate (bash test/pg_integration.sh) — LOCAL, docker
```

`test:pg` is a **local** gate (not wired into hosted CI): it spins a throwaway
`postgres:16-alpine` in docker on a random host port (trap-removed on exit), runs the
scenario against a fresh anvil, ingests it with a `DATABASE_URL` + arbiter indexer,
asserts `/head` `/notes` `/history`, then **kills and restarts** the indexer against the
same postgres and asserts it **resumed from the block cursor** (logs `resume from block
N`, N>0 — not a block-0 replay) serving byte-identical state. Requires docker + the CPU
proving artifacts under `circuits/out/`. It is the **local correctness gate** for the
containerised stack; hosted CI only build-tests the image (`indexer-image` job, above),
never `docker compose up` — see the Docker / compose section.

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
  tree.ts         MirrorTree: ImtTree mirror + per-leaf records + batch subtrees + path builder + snapshot/rebuild (resume)
  store.ts        StorePort + InMemoryStore: ingested events / alarms / nullifiers / cursor
  disclosure.ts   disclosureHash verify + alarm classification (chain fold from @bongtu/sdk/envelope)
  ledger.ts       LedgerPort + shared pure deriveOp (all crypto) + InMemoryLedger (arbiter note ledger + history)
  postgres.ts     PostgresStore + PostgresLedger: persist derived state + boot-reconstruct + resume (raw pg, no ORM)
  schema.sql      idempotent Postgres schema (events / nullifiers / leaves / cursor / notes / history / alarms)
  api/            router + one file per route (see Endpoints above)
test/             unit tests + the anvil conformance scenario (run.sh) + the Postgres integration gate (pg_integration.sh)
```

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE).
