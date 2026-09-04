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
| `GET /events?cursor=&limit=` | the ciphertext feed a wallet trial-decrypts: per op `{ seq, txHash, blockNumber, kind, epoch, ecdhPublicKey, encryptionNonce, slices[], ciphertext[], disclosure? }`. Consumer (op-module) entries — kinds `depositPriv` / `transferPriv` / `transfer10x2Priv` / `withdrawPriv` / `disbursePriv` — additionally carry `viewTags[]` (the per-output scan pre-filter), per-output `kemCiphertexts[]` (small ops), and for `disbursePriv` the `batchId`, the published `outputCommitments[]`, and `kem: { status, chunkCount, acceptedCount, kemCiphertexts? }` — the chunk-transport state, `status` ∈ `complete` / `pending` / `withheld` / `accepted-unassembled` (see below) | none |
| `GET /path/{leafIndex}` | `{ leafIndex, siblings[], pathIndices[], root }`; 404 out of range; **422** for an **enterprise** disburse-batch interior leaf in public mode. A **consumer** (`disbursePriv`) batch interior serves in **both** modes: its leaves were published as calldata and fold-verified against the proof's `subtreeRoot` before the fill | none for a single-append leaf (siblings are public chain data) or a fold-verified consumer batch interior (its siblings are published chain data too); **bjj signature or view token + leaf ownership** for an enterprise batch-interior leaf in arbiter mode (its siblings are other recipients' commitments) — 400/401 unauthenticated, **403** for a leaf the proven owner does not hold |
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
   ENTERPRISE batch /path -> 422         ENTERPRISE batch /path served to its proven owner only
   consumer batch /path auth-free        consumer batch /path auth-free (same as public)
```

The read-auth governs *who may query*, not what the instance can see. An arbiter-mode indexer is
institution-internal infrastructure and must be operated as such; the key is held in memory only and
is never logged, never returned, and never printed alongside the connection string.

The batch-interior `/path` rule is per batch **class**, not global. An **enterprise**
(`disburse`) batch publishes only its subtree root; its interior leaves exist off-chain solely
because the arbiter decrypted the authority envelope, so in public mode those paths are
structurally unservable — the sibling leaves are other recipients' encrypted commitments — which
is why they 422 rather than 500. A **consumer** (`disbursePriv`) batch publishes its full
commitment run as calldata, and the indexer fold-verifies that run against the proof's
`subtreeRoot` before filling the batch — the interiors are then the same privacy class as
single-append leaves and serve **auth-free in both modes**.

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

A **consumer** disburse (`disbursePriv`) runs the extended form of the same duty: canonical shape,
the extended fold against the proof's `disclosureHash`, **and** the published commitment run folded
to the on-chain `subtreeRoot`. Any failure classifies into the same statuses and alarms the same
way; only a fully-verified publication fills the batch (which is what makes its `/path` interiors
auth-free above). Design rationale: `.dev/op-module-design.md` §4.4.

## Consumer op family: the module event stream

The consumer (no-auditor) ops are emitted by **registered op modules**, not the pool, which adds
three ingest obligations this section owns (mechanics and how-to-run: `apps/indexer/README.md`;
design rationale: `.dev/op-module-design.md`).

**The module-registry mirror is pool-derived, and dispatch is address-gated.** The registered-module
set is mirrored from the pool's `ModuleRegistered`/`ModuleRemoved` stream, which is *balanced by
construction* (the pool reverts no-op transitions), so a double-add or remove-of-unknown is treated
as ingest corruption, not tolerated state. Only **pool-emitted** logs ever drive the mirror — and
that is one instance of the general dispatch rule: event decoding matches on topic0 across the
combined ABI, so which handler a log may reach is decided by its **emitter address**, never its name.
Pool-family events apply only from the pool, `Swept` only from the PortalFactory, and the consumer
op family only from the current watch-set: registered modules plus removed modules still owed kem
chunk accepts (`submitDisburseKemChunk` outlives deregistration). Logs from any other emitter are
not ours and are dropped silently.

**`OpApplied` is the per-op audit anchor.** The pool emits `OpApplied` inside every `applyOp`, and
each consumer op event must consume its tx's next `OpApplied` and agree with it — module
attribution, shape (nullifier/leaf counts, start index, subtree root) and resulting root — the same
mirror-invariant posture as the `Appended` commitment cross-check; disagreement halts ingest. The
reverse gap is surfaced too: an `OpApplied` left unconsumed after a pass (a module mutated the tree
with no decodable family event) produces an alarm-class warning naming the module and tx, without
wedging ingest.

**Kem chunk bytes are a documented calldata-fetch deviation from the logs-only rule.** A consumer
disburse's per-output KEM ciphertexts are too large for one tx and arrive in K chunk transactions
whose bytes live in **calldata only** (`DisburseKemChunkAccepted` re-emits nothing); ingest fetches
each accepting tx and re-verifies the bytes against the batch-time keccak commitments the chain
already enforced — a mismatch there means the RPC lied and halts. Everything else the indexer serves
still derives from logs alone. The `/events` `kem.status` projection distinguishes chunks *missing
on-chain* (`pending` inside the `KEM_GRACE_SECONDS` window, `withheld` past it) from *accepted but
unassembled* (`accepted-unassembled`: every accept landed — nothing was withheld — but some chunk's
bytes could not be decoded from its submit calldata, e.g. a wrapped submission). Accepted bytes are
on-chain, so recovery is expected: the indexer re-attempts the fetch+decode at every boot. All of
these are operational transport states, never `/alarms` entries — nothing on-chain-provable was
violated. Module-*emitted* inconsistencies (an accept for an unknown batch, an out-of-range or
duplicate chunk index) degrade the same way: warn and drop, with the chunk simply counting as
missing — a hostile module emission must cost at most its own batch's discoverability, never the
poll loop.

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

## Name directory

`/names` is the one indexer-owned **mutable** surface — every other table mirrors chain
events; a name registration has no on-chain footprint. `name → { owner bjj pubkey,
stealth meta-address, optional consumer pair }` records are accepted only under the
owner's bjj EdDSA-Poseidon signature over the full payload (domain-separated from the
read-auth and view-token tuples, `|now − ts| ≤ 300s`), so the registry is
**availability-trusted only**: a hostile indexer can withhold a name, never forge or
splice one. Ownership rule: first-come per name; the same owner may update
(stealth-meta rotation); transfer does not exist. Served identically in public and
arbiter mode — the records are public identity material. Names are DNS-label-shaped
(3–32 lowercase alnum, interior hyphens) so a later ENS/CCIP-read gateway can serve the
same records without migration.

A record optionally carries the **consumer pair** — `noteViewPub` (the note-layer bjj
view pubkey) and `kemEk` (the ML-KEM-768 encapsulation key) — everything a payer needs
to seal a consumer op's outputs to the name. The pair is **required together** (a lone
half is an unusable identity → 400), and the ek is validated by an actual
encapsulation before it is stored, so a payer can never burn a note against garbage.

Registrations come in **two signature forms, selected deterministically by payload
shape — no dual-try**. A payload carrying neither consumer field verifies as **v1**:
`nameAuthMessage` over the 3-segment binding (`name|viewPub|spendPub`) under the
`bongtu/name-auth-v1` domain tag. A payload carrying both verifies as **v2** only: the
5-segment binding (`…|noteViewPub|kemEk`) under `bongtu/name-auth-v2` — the tags are
disjoint, so no signature verifies under the other form. **v1 writes are read-only for
the consumer columns**: a legacy-signed update touches only the three legacy fields and
preserves any consumer pair the owner set, so a captured v1 registration replayed
inside the auth window re-asserts only what it already bound. Setting, rotating or
clearing the pair requires a v2 signature; clearing is explicit — the owner signs both
full-width zero-sentinels. Rationale and the exact digest forms:
`.dev/op-module-design.md` §6.1–§6.4.

Wire shapes + the client half (`buildNameRegistration`, `buildNameRegistrationV2`,
`registerName`, `resolveName`): `@bongtu/core/indexerApi`; server half:
`apps/indexer/src/names.ts` + `api/routes/names.ts`; stealth meta-address semantics:
`packages/core/src/notes/stealth.ts`.

## Announcement feed

Stealth withdraws pair each `Withdrawn` with a `WithdrawAnnouncement` event; the
ingest attaches it to the withdraw feed entry (payload-persisted, no extra
table) and `/announcements` serves the projection. Plain (non-stealth) withdraws
never enter the feed: the contract emits the pair unconditionally with a
zero-sentinel ephemeral key, and the ingest applies the core
`isStealthAnnouncement` predicate once, attaching nothing for the sentinel. Two read paths, one privacy
story: the PUBLIC cursor feed is the trustless scan-all a wallet walks with its
view key; the ARBITER-MODE `?owner=` slice serves only the caller's own rows
behind the `/notes` read-auth — zero marginal disclosure, because the arbiter
already learns each withdraw's owner from the authority envelope, and the
per-owner attribution is exactly the ledger's decrypted history. A wallet that
distrusts the indexer falls back to the public feed; announcements are
calldata-carried, so a tampered one can only break discovery, never redirect
the proof-bound payout.
