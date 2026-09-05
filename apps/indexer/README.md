# @bongtu/indexer

The bongtu read-side service: it ingests `BongtuPool` events from an RPC, mirrors the on-chain
IMT, and serves the merkle-path / ciphertext-feed / alarm API the wallet apps depend on. It is
read-only on-chain (opens no wallet, sends no transactions).

This README owns how to run, test and deploy it. The guarantees and the full wire contract — every
route, the read-auth and view tokens, the two modes, the alarm classes, the consumer op family —
are owned by [`docs/indexer.md`](../../docs/indexer.md); wire shapes by
[`@bongtu/core/indexerApi`](../../packages/core/README.md).

The mode is decided at boot ([`docs/indexer.md` § Trust
boundary](../../docs/indexer.md#trust-boundary-arbiter-mode)): **public** (default, no key — chain
data only) or **arbiter** (`AUTHORITY_KEY` set, plus `AUTHORITY_KEM_KEY` against a hybrid pool),
which decrypts every op's authority envelope and is institution-internal by nature — the keys are
held in memory only, never logged, never returned (repo [`CLAUDE.md`](../../CLAUDE.md) rule).

## Run

**Postgres is required** (`DATABASE_URL`); the recommended way to run is the compose stack below
(`docker compose up --build`), which provides it. To run the process directly, point
`DATABASE_URL` at any reachable Postgres:

```sh
DATABASE_URL=postgres://… npm start                        # defaults: local anvil RPC, port 8600
DATABASE_URL=postgres://… RPC=https://rpc-testnet.maroo.io npm start   # the live pool (read-only)
```

Env knobs (`src/index.ts`):

| env | default | meaning |
|---|---|---|
| `RPC` / `LIVE_RPC` / `E2E_RPC` | anvil `127.0.0.1:8545` | RPC endpoint |
| `POOL` | from `deploy/addresses.<CHAIN_ID>.json` | pool address |
| `CHAIN_ID` | the sdk `CHAIN_ID` | chain id for the addresses file |
| `START_BLOCK` | `0` | first block to replay |
| `PORT` | `8600` | HTTP port |
| `POLL_MS` | `3000` | incremental re-ingest interval (`0` = off) |
| `AUTHORITY_KEY` | unset | arbiter bjj private key → arbiter mode |
| `AUTHORITY_KEM_KEY` | unset | the arbiter's ML-KEM-768 decapsulation key — required in arbiter mode against a hybrid pool (the KEM boot guard refuses to boot without it, [`docs/indexer.md`](../../docs/indexer.md#the-kem-boot-guard)) |
| `TOKEN_SECRET` | generated per boot | HMAC secret for `/auth` view tokens (arbiter mode). When generated, boot warns that issued tokens reset on restart — set it to keep wallet logins across restarts |
| `PUBLIC_URL` | loopback listen address | comma-separated origin(s) clients reach this indexer on. `/auth` signatures are bound to one of them, so **a wallet served through the same-origin `/indexer` proxy must list the WALLET's origin(s)**, not the indexer's (`https://bongtu.fractalyze.io,https://…vercel.app`). A wrong value is not fatal but silently drops every login to the tokenless path (balance loads once, then cannot refresh); boot prints what was resolved |
| `DATABASE_URL` | **required** | Postgres connection string (persist + boot-resume). Unset → the service refuses to boot |
| `PORTAL_FACTORY` | unset | PortalFactory address → portal deposits live (`POST /pay/{name}` + `/portal/*`, Swept-log ingest). Unset → those routes 404 and boot logs one line saying so |
| `LOG_CHUNK` | `50000` | getLogs chunk size in blocks — the one read-side tuning knob (auto-bisects on RPC range caps; `10000` suits rate-capped public RPC tail scanning) |
| `KEM_GRACE_SECONDS` | `3600` | seconds an incomplete consumer-disburse chunk set reads kem-`pending` on `/events` before kem-`withheld` (OPMOD §5). Parsed once at boot — a non-numeric value refuses to boot |
| `SOLANA_RPC` | unset | **backend switch**: set => the service ingests the SOLANA rail (`src/solana/`) instead of the EVM pool — signature-cursor ingest, inner-instruction dispatch, self-CPI event decode, per-op mirror assertion (SOLR §3.2). The API surface is identical; `RPC`/`POOL` are ignored. Requires `SOLANA_TREE` (the TreeState account, base58); `SOLANA_PROGRAM` defaults to the program's `declare_id!`. Refuses to boot combined with `AUTHORITY_KEY` ([`docs/indexer.md` § Trust boundary](../../docs/indexer.md#trust-boundary-arbiter-mode)) |
| `DISCLOSURE_DIR` | unset | directory of institution-held disburse disclosure blobs (`{startLeafIndex}.json`, a JSON array of 32-byte hex elements) — what `GET /disclosure` serves and the per-batch boot invariant re-checks against `DisburseBatch.disclosureHash` (SOLR §3.3.2). A mismatching blob alarms `mismatch`; a batch unserved past `DISCLOSURE_GRACE_SECONDS` (default `3600`) alarms `withheld` |

Workspace install and shared tooling: root [`README.md`](../../README.md). Chain access is viem, a
normal dependency; the pool ABI loads from the Foundry artifact
`chains/evm/out/BongtuPool.sol/BongtuPool.json` (run `forge build` in `chains/evm` first — the
Docker image bakes in the committed copy [`abi/BongtuPool.abi.json`](abi/README.md) instead, which
CI drift-gates against the built ABI).

## Docker / compose

A 2-service stack — **postgres + indexer** — is defined at the repo root
([`docker-compose.yml`](../../docker-compose.yml)); the prover (GPU) and the static web apps are
deliberately out of scope.

```sh
docker compose up --build                     # postgres (named volume + healthcheck) then
                                              # the indexer, RPC defaulting to a HOST anvil
                                              # on :8545 via host.docker.internal
cp .env.compose.example .env.compose          # edit RPC / POOL / AUTHORITY_KEY / START_BLOCK
docker compose --env-file .env.compose up --build
```

Compose starts postgres first (gated on `pg_isready`), then the indexer, which sets `DATABASE_URL`
at the postgres service, applies `src/schema.sql` on boot (idempotent), and ingests. The named
`pgdata` volume persists across `up`/`down`, so a restart **resumes** from the block cursor. Knobs
are interpolated from the shell / `--env-file` with sane defaults (`.env.compose.example`); leave
`POOL` empty to fall back to the baked-in `deploy/addresses.<CHAIN_ID>.json` (the sdk `CHAIN_ID` =
the live pool). The indexer serves `GET /health` on **8600**, and the container's `HEALTHCHECK`
reports healthy once `/health` returns `ok:true`. `AUTHORITY_KEY` flips the container to arbiter
mode (institution-internal — see [`CLAUDE.md`](../../CLAUDE.md)).

The image ([`apps/indexer/Dockerfile`](Dockerfile), context = repo root) is multi-stage: a builder
trims the npm workspace to `packages/core` + `apps/indexer` (a lockfile-pinned
`npm ci --workspace …`, no react/vite); the slim non-root runtime copies the installed tree, the
raw `.ts` source (run via `node --import tsx`), the addresses file, and the committed pool ABI
placed at `chains/evm/out/BongtuPool.sol/BongtuPool.json`, so the image is self-contained (no
foundry in the build) and reproducible. CI builds this image **build-only** (`indexer-image` job);
`docker compose up` and the pg integration test below stay LOCAL gates.

## Testing

```sh
npm run test:unit    # anvil-free units: tree + disclosure + ingest + config + persist atomicity (fast inner loop)
npm run typecheck    # tsc --noEmit
npm test             # the full conformance gate (bash test/run.sh) — heavy, POSTGRES-backed
npm run test:pg      # the Postgres resume/crash gate (bash test/pg_integration.sh) — LOCAL, docker
```

`test:pg` is a **local** gate (not wired into hosted CI): it spins a throwaway
`postgres:16-alpine` in docker on a random host port (trap-removed on exit), runs the scenario
against a fresh anvil, ingests it with a `DATABASE_URL` + arbiter indexer, asserts `/head`
`/notes` `/history`, then **kills and restarts** the indexer against the same postgres and asserts
it **resumed from the block cursor** (logs `resume from block N`, N>0 — not a block-0 replay)
serving byte-identical state. Requires docker + the CPU proving artifacts under `circuits/out/`.
It is the local correctness gate for the containerised stack; hosted CI only build-tests the image
(`indexer-image` job, above), never `docker compose up`.

The conformance gate starts its own anvil on port **8552** (override `INDEXER_E2E_PORT` if that
port is taken), deploys a fresh B=16 pool, drives the full scenario (deposit → disburse → transfer
→ withdraw → tampered disburses), and asserts mirror==contract at every step, path folding,
trial-decrypt, the alarm classes, and the arbiter-mode ledger + `/notes` + within-batch `/path`.
Being Postgres-only, it ingests into **real Postgres**: `run.sh` honors an exported
`TEST_DATABASE_URL` (admin connection string; CI provides a postgres **service container**) and
otherwise spins a throwaway `postgres:16-alpine` docker container (trap-removed). If neither is
possible it SKIPs with a loud banner — never a silent pass. It also needs the CPU proving
artifacts under `circuits/out/` (`cd circuits && bash build/prove_all.sh` first) and runs as the
`indexer-conformance` job in CI — treat it as a final gate, not a per-iteration loop (repo
`CLAUDE.md` "Heavy gates").

## Layout

```
src/
  index.ts        runnable service: env → ingest → serve (+ tail polling)
  chain.ts        config resolution + pool ABI (viem) plumbing
  host.ts         IndexerHost (the 18-member read-model surface routes consume) + the engine-neutral base (poll/health, close)
  persist.ts      declared persistence participants + the ONE atomic persist (flush order, crash hook, commit-after-COMMIT)
  ingest.ts       Indexer (EVM engine): event ingest + correlation, applyLogs
  tree.ts         MirrorTree: ImtTree mirror + per-leaf records + batch subtrees + path builder + snapshot/rebuild (resume)
  store.ts        StorePort + InMemoryStore (PostgresStore's sync read-model component): events / alarms / nullifiers / cursor
  disclosure.ts   disclosureHash verify + alarm classification (chain fold from @bongtu/core/envelope)
  ledger.ts       pure deriveOp (all the ledger crypto) + record helpers + ledger types
  modules.ts      the op-module registry mirror (consumer op family watch-set)
  kemchunks.ts    consumer-disburse kem-ct chunk assembly (calldata fetch + keccak recheck)
  names.ts        the name-directory records + v1/v2 signature forms
  portal.ts       portal issuance records + swept/unswept state
  postgres.ts     PostgresStore + PostgresLedger (the ONE runtime backend): persist derived state + boot-reconstruct + resume (raw pg, no ORM)
  schema.sql      idempotent Postgres schema (events / nullifiers / leaves / cursor / notes / history / alarms)
  solana/         the Solana rail backend (SOLANA_RPC switch)
  api/            router + readAuth + viewtoken + one file per route
test/             unit tests + the anvil conformance scenario (run.sh) + the Postgres integration gate (pg_integration.sh)
```

## Ops — dev-box deployment (manual by choice)

The public arbiter indexer runs on the fractalyze GPU dev box. Deploys are **manual** — indexer
releases are infrequent and each one moves the live arbiter state, so a human runs them
deliberately rather than on every push:

- **Deploy clone**: `/home/a41/bongtu-deploy` — a dedicated checkout (separate from any dev
  working tree) that runs the compose stack above. Redeploy:

  ```sh
  cd /home/a41/bongtu-deploy
  git fetch origin main && git reset --hard origin/main
  docker compose --env-file .env.compose up -d --build
  curl -fsS localhost:8600/health   # gate: "ok": true, cursor advancing
  ```

  The stack itself is always-on (`restart: unless-stopped`; Postgres cursor gap-resumes across any
  restart).
- **Public endpoint**: Tailscale Funnel maps `https://gpu-server.tailec11d1.ts.net:10000` → local
  `:8600` (`tailscale funnel --bg --https=10000 http://127.0.0.1:8600`; ports 443/8443 on that
  node belong to other apps). The mapping persists across reboots.
- **Secrets**: `AUTHORITY_KEY` (arbiter bjj key) and the RPC URL live ONLY in the deploy clone's
  gitignored `.env.compose` (mode 600) — never in repo history.

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE).
