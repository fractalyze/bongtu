# Indexer

`apps/indexer` is the read side: it ingests `BongtuPool` events, maintains an off-chain mirror of
the on-chain IMT, and serves merkle paths, the ciphertext feed, disclosure alarms and — in arbiter
mode — a decrypted per-owner note ledger. It is read-only on-chain: no wallet, no transactions.

This page owns the guarantees and the wire contract. How to run it, the env table and the compose
stack are owned by `apps/indexer/README.md`.

## Mirror invariant

`MirrorTree` (`src/tree.ts`) wraps the same `ImtTree` class the contract's differential test pins
against, and applies the two low-level tree events — `Appended` and the batch attach — each of which
carries the resulting on-chain root. So the mirror is asserted against the contract **per insert**,
not merely at head, and again against `root()` / `nextLeafIndex()` at the scanned head block. Every
endpoint serves this ingested state, which keeps the API mutually consistent and available even when
the RPC is not.

## Ingest, persist, resume

Postgres is the one storage backend. `DATABASE_URL` is mandatory: with it unset the service prints
one line and exits non-zero (`databaseUrlError` in `src/chain.ts`). There is no in-memory fallback:
`InMemoryStore` is the synchronous read-model component `PostgresStore` wraps (and, standalone, the
pre-boot placeholder that lets `/health` answer before the first ingest and the double the anvil-free
unit test drives at `applyLogs` level) — never a selectable backend.

```
  boot
    |
    +-- bootPostgres: rebuild MirrorTree from the `leaves` table, rehydrate the ledger
    |     |
    |     +-- cursor >= 0 ?  ASSERT reconstructed root == contract root @ cursor block
    |     |                  ASSERT reconstructed nextLeafIndex == contract @ cursor block
    |     |                  -> resume from cursor + 1
    |     +-- no cursor   ->  fresh ingest from START_BLOCK
    |
    +-- getLogs [from .. head]  --> applyLogs (pure)  --> buffered rows
    |
    +-- persist(head):  ONE transaction
          { event rows, nullifiers, leaf DELTA, notes/history/alarms, block cursor := head }
          COMMIT  -> buffers cleared, in-memory cursor advanced
          ROLLBACK-> nothing moved; the next poll re-scans from the unadvanced cursor
```

Two properties fall out and both are load-bearing:

- **Gap-only resume.** A restart replays from `cursor + 1`, not from `START_BLOCK`. The rows and the
  cursor commit together, so a crash mid-persist can never leave the `leaves` table ahead of the
  cursor — the state a restart reconstructs is always mutually consistent with the resume point.
  `test/pg_resume.ts` exercises the atomicity window deliberately.
- **Resume is verified, not assumed.** The reconstructed root and `nextLeafIndex` are compared
  against the contract *pinned to the cursor block* before any new log is applied. A mismatch throws
  at boot rather than serving a silently-forked tree.

Leaf writes are a delta (only leaves recorded since the last flush). The tree is not stored as
nodes; it is rebuilt from the `leaves` table in `O(n)` at boot. Schema: `src/schema.sql`, applied
idempotently on every boot.

The decrypt/derive step (KEM decapsulation → binding check → envelope → notes, spent marks, history,
envelope alarms) is one pure function, `deriveOp` in `src/ledger.ts`, called once per op — crypto and
recording never mix.

## Dual-ABI ingest

Adding `kemBinding` + `kemCiphertext` to the op events changed their topic0, so the pool has two
event generations and the indexer carries **both** ABI fragment sets. A pre-upgrade (V1) log decodes
without the KEM fields and enters the ledger as `kem: null`; a hybrid log carries
`kem: { binding, ciphertext }`. The gate is structural, not arithmetic: there is no epoch lookup and
no block-number comparison anywhere in the path, so pre-KEM history cannot false-alarm no matter how
the epoch list evolves. The current pool is hybrid from its first block and has no pre-KEM history
of its own; the V1 fragments are kept because the decode path must stay safe against any pool this
build is pointed at, and the conformance test exercises both vintages.

A V1-only build against a hybrid pool would fail **silently**, which is the reason for the boot
guard below: `getLogsChunked` wraps `parseLog` in try/catch-continue, so unknown-topic0 envelope
events are skipped while `Appended` / `SubtreeAppended` keep the tree mirror advancing. `/health`
would stay green while the note ledger and the feed under-recorded.

## The KEM boot guard

`kemBootGuard` runs before the service serves anything. It reads
`arbiterKemPkHash(currentEpoch())` and refuses to boot in three configurations:

| condition | why refusing is right |
|---|---|
| pool is in a KEM epoch, build has a V1-only ABI | every op envelope would be silently skipped |
| pool is in a KEM epoch, arbiter mode, no `AUTHORITY_KEM_KEY` | nothing could be decapsulated |
| the encapsulation key **embedded in** `AUTHORITY_KEM_KEY` hashes differently from the on-chain value | it would record a false "kem binding mismatch" tamper verdict against every honest op |

The third check derives the encapsulation key from the secret (`kemPkFromSecret`, the FIPS 203 `dk`
layout) rather than trusting a separately configured public key, so a mismatched pair cannot slip
through. The probe is fail-closed: only a `CALL_EXCEPTION` — a missing or reverting getter — is read
as "this is a pre-KEM V1 pool". A transient RPC error propagates and the boot fails, rather than
being folded into a benign-looking verdict.

## Log scanning and `LOG_CHUNK`

`getLogsChunked` (`src/ingest.ts`) requests logs **filtered server-side by the pool address** and
walks the block range in `LOG_CHUNK`-sized windows (default 50,000). Any provider error on a window
bisects it and retries both halves, recursively, down to a single block — at which point the error
is rethrown. That makes the scanner RPC-agnostic: a provider whose `eth_getLogs` cap is below
`LOG_CHUNK` is absorbed by the bisect instead of failing the ingest, at the cost of the extra
retries — which is why the tuning guidance for rate-capped providers sits in the README's env table.

Block timestamps for the arbiter history feed are fetched once per distinct block, in waves of 16,
so a cold backfill does not open one socket per block.

## HTTP API

| route | serves | auth |
|---|---|---|
| `GET /head` | `{ root, nextLeafIndex }` of the ingested mirror | none |
| `GET /events?cursor=&limit=` | the ciphertext feed a wallet trial-decrypts: per op `{ seq, txHash, blockNumber, kind, epoch, ecdhPublicKey, encryptionNonce, slices[], ciphertext[], disclosure? }` | none |
| `GET /path/{leafIndex}` | `{ leafIndex, siblings[], pathIndices[], root }`; 404 out of range; **422** for a disburse-batch interior leaf in public mode | none for a single-append leaf (siblings are public chain data); **bjj signature or view token + leaf ownership** for a batch-interior leaf in arbiter mode (its siblings are other recipients' commitments) — 400/401 unauthenticated, **403** for a leaf the proven owner does not hold |
| `GET /nullifiers` | the spent-nullifier set derived from events | none |
| `GET /alarms` | one discriminated feed: every non-passing disclosure (`type:"disclosure"`) plus, arbiter mode only, envelope cross-check failures (`type:"envelope"`) | none |
| `GET /health` | `{ ok, lastBlock, nextLeafIndex, batchSize, alarms, lastSuccessAt, lastError, lastErrorAt, consecutiveFailures }`; `ok` is false when the tail poll is persistently failing | none |
| `GET /notes?owner=&ts=&sig=` | one owner's decrypted notes `[{ owner, value, salt, leafIndex, commitment, txHash, spent }]` | **bjj signature, arbiter mode only** |
| `GET /history?owner=&ts=&sig=[&limit=&before=]` | one owner's activity feed `[{ kind, counterparty, amount, txHash, blockTimestamp, seq }]`, newest first — **one page** as `{ items, nextBefore }` when `limit` or `before` is present, the whole feed as a bare array when neither is (see below) | **bjj signature, arbiter mode only** |

Wire shapes are typed by `@bongtu/core/indexerApi`; the routes type their response bodies against
them and `buildNotesUrl` / `buildHistoryUrl` are the one client-side URL builder.

A disburse derives one "received" per non-self output **and one aggregated "sent" for the payer**
(amount = the batch's non-self total, `counterparty` null — 255 per-payee rows would bury the
payer's feed, and a batch has no single other party). History rows are derived at ingest and
persisted, so a rule change reaches already-ingested batches only through a from-scratch rescan.

**Paging `/history`.** A payroll account's feed grows without bound, so the wallet reads it one page
at a time: `limit` (default 50, max 200) and `before`, an **exclusive upper bound on `seq`**. The
cursor is a seq rather than an offset because `seq` is assigned once in chain-apply order and never
renumbered — a page stays the same page while new activity lands ahead of it. The response is
`{ items, nextBefore }`, where `nextBefore` is the last item's `seq` when the page came back **full**
and `null` once the feed is exhausted; a client pages until it is null. Non-digit, empty, negative
or over-cap values are 400s (`Number("")` is 0, so the parse is digits-only, not `Number()`).

A request carrying **neither** param still gets the legacy bare array of the whole feed — the
deployed wallet parses an array and would read an envelope as zero activity. That branch exists for
one release and goes away once no client in the wild predates `fetchHistoryPage`.

The filter is applied in the read model, not in SQL: each owner's history array is kept sorted by
ascending `seq` at insert (`pushHistory`), so a page is a binary search for `before` plus a backwards
walk — no per-request copy or sort of a feed that may hold thousands of rows.

**Read auth on `/notes` and `/history`.** `owner` is the compressed bjj pubkey; `sig` is a bjj
EdDSA-Poseidon signature over `Poseidon(ownerPub.x, ownerPub.y, ts)` verified against **the queried
key**; `ts` is unix seconds and the request is rejected unless `|now − ts| ≤ 300`, which bounds
replay to a five-minute window. Malformed owner or missing `ts`/`sig` → 400; wrong key or expired
`ts` → 401. The check runs before any ledger lookup, so it never leaks whether an owner has notes.

`/notes` and `/history` are composed into the route table **at build time**, only when the indexer
holds the arbiter key. A public indexer returns 404 for them: the routes do not exist, rather than
existing and refusing.

## Trust boundary: arbiter mode

Setting `AUTHORITY_KEY` to the arbiter's bjj private key flips the indexer into arbiter mode. That
instance decrypts **every** operation's authority envelope, so it holds every owner's notes,
balances and counterparties in plaintext. Against a hybrid pool it also needs `AUTHORITY_KEM_KEY`,
the ML-KEM-768 decapsulation key — both halves of the envelope key, both under the same handling
rule: held in memory only, never logged, never returned, never printed next to the connection
string. `docker-compose.yml` forwards both.

```
   public indexer                        arbiter indexer  (AUTHORITY_KEY + AUTHORITY_KEM_KEY)
   ─────────────                         ───────────────
   chain data only                       chain data + EVERY owner's decrypted notes
   /notes, /history absent (404)         /notes, /history present, per-owner signature-gated
   batch-interior /path -> 422           batch-interior /path served to its proven owner only
```

The read-auth governs *who may query*, not what the instance can see. An arbiter-mode indexer is
institution-internal infrastructure and must be operated as such; the key is held in memory only and
is never logged, never returned, and never printed alongside the connection string. Public-mode
batch-interior paths are structurally unservable — the sibling leaves are encrypted to other
recipients — which is why they 422 rather than 500.

## Disclosure alarms

For every `disburse` the indexer recomputes the Poseidon chain over the emitted ciphertext
(`disclosureChain` from `@bongtu/core/envelope`, the same fold the circuit commits to) and compares
it to the on-chain `disclosureHash`. Classification (`src/disclosure.ts`):

| status | condition | meaning |
|---|---|---|
| `verified` | fold equals `disclosureHash` | the only status that stays off `/alarms` |
| `mismatch` | fold differs and the payload is not exactly the receiver run | proven tamper or junk |
| `unverifiable` | payload is exactly `4·B` elements | authority envelope not published; the chain cannot be completed |
| `withheld` | nothing published | no ciphertext at all |

`unverifiable` and `withheld` alarm too, deliberately: a receiver-only emission is indistinguishable
from tampered receiver-only bytes, so staying silent would make the alarm duty bypassable by
truncating what is published. This is the operational half of enforced disclosure — the contract
guarantees the bytes are *there*, the indexer proves they are *right*. See
[security-model.md](security-model.md).

## Envelope alarms and the KEM binding

The `envelope` alarm class on `/alarms` is arbiter-mode only, and it now covers two checks. The
older one is the envelope cross-check: the decrypted authority plaintext must reproduce the
operation's on-chain commitments. The newer one closes the post-quantum loop, and it runs **first**,
before any decryption.

For every hybrid op the arbiter decapsulates `kemCiphertext` under `AUTHORITY_KEM_KEY`, recomputes
`Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]])`, and compares it to the proof's `kemBinding`. On a
mismatch the op **stops**: no notes recorded, no batch fill, no history, envelope withheld — and an
alarm carrying the tx hash plus the expected and recomputed values. The chain can only check that
the ciphertext is 1088 bytes, so this is where a junk-wrapped encapsulation is caught
([security-model.md](security-model.md#post-quantum-the-hybrid-authority-envelope-key)).

A ciphertext malformed enough that decapsulation itself throws takes the same path — alarm and
withhold — rather than propagating. That matters operationally: a throw here would re-crash on the
unadvanced cursor hitting the same op forever, turning one bad op into a permanently stalled ingest.
The one case that does throw is an op carrying KEM material with no key configured, which is a
misconfiguration the boot guard already refuses; failing loudly there is better than recording a
false tamper verdict.
