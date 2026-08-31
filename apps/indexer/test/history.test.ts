// Headless gate for the PAGED /history feed (route + read model). No anvil, no
// Postgres, no proofs: the ledger's read model is rebuilt through its REAL boot()
// path against a fake pool that returns hand-written history rows, so what is
// under test is the paging itself — the ordering invariant, the cursor, and the
// route's parameter contract.
//
//   1. READ MODEL — historyOf serves seq-desc; a `before` cursor walks the whole
//      feed exactly once with no gaps and no repeats; the boundaries (exactly-
//      limit, exhausted, empty owner, cursor past the head) each behave.
//   2. ORDERING INVARIANT — the per-owner array pushHistory maintains is ascending
//      by seq even when a producer pushes out of order. historyOf binary-searches
//      it, so a violated invariant would silently serve the wrong page.
//   3. ROUTE — the paging params validate (garbage is a 400, the cap is enforced),
//      `nextBefore` is the last item's seq only when the page came back full, and
//      the NO-PARAM request still serves the LEGACY bare array the deployed wallet
//      parses. Auth is unchanged and still runs first.
//
//   node --import tsx --test test/history.test.ts   # (== npm run test:history)

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Pool } from "pg";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { buildNotesUrl } from "@bongtu/core/indexerApi";
import type { HistoryItem, HistoryPage } from "@bongtu/core/indexerApi";

import { MirrorTree } from "../src/tree.js";
import { PostgresLedger } from "../src/postgres.js";
import { pushHistory, type LedgerHistoryItem } from "../src/ledger.js";
import { history, DEFAULT_LIMIT, MAX_LIMIT } from "../src/api/routes/history.js";
import { ViewTokenService } from "../src/api/viewtoken.js";
import type { Indexer } from "../src/ingest.js";
import type { RouteContext, RouteResult } from "../src/api/router.js";

const OWNER = deriveKeypair(555000555000555000n);
const STRANGER = deriveKeypair(777000777000777000n);
const ownerCompressed = packPubkey(OWNER.publicKey);

const HOME = "https://wallet.example";
const TOKENS = new ViewTokenService(Buffer.from("history-test-secret"), { publicUrls: [HOME] });

// --- a booted ledger over a fake pool ------------------------------------------

/** `FEED_SIZE` history rows for OWNER, seq 0..FEED_SIZE-1 in chain order. */
const FEED_SIZE = 137; // deliberately not a multiple of any page size used below

function historyRows(count: number): Record<string, unknown>[] {
  return Array.from({ length: count }, (_, seq) => ({
    owner_key: `${OWNER.publicKey[0]},${OWNER.publicKey[1]}`,
    kind: seq % 2 === 0 ? "received" : "sent",
    counterparty: null,
    amount: String(seq),
    tx_hash: `0x${seq.toString(16).padStart(4, "0")}`,
    block_timestamp: 1_700_000_000 + seq,
    seq,
  }));
}

/** A pool that answers boot()'s four SELECTs and nothing else — historyOf never
 *  touches SQL (the read model is in memory by design), so this is the whole
 *  database surface the paged feed has. */
function fakePool(rows: Record<string, unknown>[]): Pool {
  return {
    query: async (sql: string) => {
      if (sql.includes("FROM notes")) return { rows: [] };
      if (sql.includes("FROM history")) return { rows };
      if (sql.includes("FROM envelope_alarms")) return { rows: [] };
      if (sql.includes("FROM applied_ops")) return { rows: [] };
      throw new Error(`unexpected query in a read-model test: ${sql}`);
    },
  } as unknown as Pool;
}

async function bootedLedger(count = FEED_SIZE): Promise<PostgresLedger> {
  const tree = new MirrorTree(8, 4);
  const ledger = new PostgresLedger(fakePool(historyRows(count)), OWNER.formattedPrivateKey, null, 4, tree);
  await ledger.boot();
  return ledger;
}

const seqs = (items: { seq: number }[]): number[] => items.map((i) => i.seq);

// ============================ (1) READ MODEL =================================

test("historyOf with no options serves the whole feed, newest-first", async () => {
  const ledger = await bootedLedger();
  const all = ledger.historyOf(OWNER.publicKey[0], OWNER.publicKey[1]);
  assert.equal(all.length, FEED_SIZE);
  assert.deepEqual(
    seqs(all),
    Array.from({ length: FEED_SIZE }, (_, i) => FEED_SIZE - 1 - i),
    "seq descending, no re-sort needed by the caller",
  );
});

test("paging by cursor walks the feed exactly once — no gaps, no repeats", async () => {
  const ledger = await bootedLedger();
  const limit = 20;
  const walked: number[] = [];
  let before: number | undefined;
  let pages = 0;
  for (;;) {
    const page = ledger.historyOf(OWNER.publicKey[0], OWNER.publicKey[1], { limit, before });
    pages++;
    walked.push(...seqs(page));
    if (page.length < limit) break;
    before = page[page.length - 1].seq;
    assert.ok(pages < 100, "cursor did not advance — the walk is not terminating");
  }
  assert.equal(pages, Math.ceil(FEED_SIZE / limit));
  assert.deepEqual(
    walked,
    Array.from({ length: FEED_SIZE }, (_, i) => FEED_SIZE - 1 - i),
    "the concatenated pages are the whole feed in seq-desc order",
  );
  assert.equal(new Set(walked).size, FEED_SIZE, "no item was served twice");
});

test("page boundaries: exactly-limit, exhausted, empty owner, cursor past the head", async () => {
  const ledger = await bootedLedger();
  const at = (opts: { limit?: number; before?: number }): LedgerHistoryItem[] =>
    ledger.historyOf(OWNER.publicKey[0], OWNER.publicKey[1], opts);

  // exactly-limit: a full page whose feed happens to end right there.
  assert.deepEqual(seqs(at({ limit: 3, before: 3 })), [2, 1, 0], "the last three items");
  assert.deepEqual(at({ limit: 3, before: 0 }), [], "before=0 excludes seq 0 — nothing is below it");

  // a cursor above the newest seq is not an error: it just means "from the top".
  assert.deepEqual(seqs(at({ limit: 2, before: FEED_SIZE + 1000 })), [FEED_SIZE - 1, FEED_SIZE - 2]);

  // limit larger than what remains returns what remains, not padding.
  assert.equal(at({ limit: 500 }).length, FEED_SIZE);

  // an owner with no activity at all.
  assert.deepEqual(ledger.historyOf(STRANGER.publicKey[0], STRANGER.publicKey[1], { limit: 10 }), []);
  assert.deepEqual(ledger.historyOf(STRANGER.publicKey[0], STRANGER.publicKey[1]), []);
});

// ============================ (2) ORDERING INVARIANT =========================

test("pushHistory keeps each owner's list ascending by seq, even out of order", () => {
  const byOwner = new Map<string, LedgerHistoryItem[]>();
  const item = (seq: number): LedgerHistoryItem => ({
    kind: "received",
    counterparty: null,
    amount: "1",
    txHash: "0xaa",
    blockTimestamp: 1,
    seq,
  });
  // The producers push ascending (apply() stamps a monotonic seq, boot() replays
  // ORDER BY seq ASC) — but historyOf BINARY-SEARCHES the result, so the belt has
  // to hold for an out-of-order push too, or a page would silently be wrong.
  for (const s of [0, 1, 2, 5, 3, 9, 4]) pushHistory(byOwner, OWNER.publicKey, item(s));
  const arr = byOwner.get(`${OWNER.publicKey[0]},${OWNER.publicKey[1]}`);
  assert.deepEqual(seqs(arr ?? []), [0, 1, 2, 3, 4, 5, 9]);
});

// ============================ (3) ROUTE ======================================

function call(ledger: PostgresLedger | null, query: string): RouteResult {
  const ix = { arbiterMode: true, ledger } as unknown as Indexer;
  const ctx: RouteContext = { ix, tokens: TOKENS, params: [], query: new URLSearchParams(query) };
  return history.handle(ctx) as RouteResult; // history is a sync route
}

/** The signed-query auth the route already had — reused verbatim so these tests
 *  exercise paging, not auth (which viewtoken.test.ts owns). */
const authQuery = (): string =>
  new URL(buildNotesUrl("http://x", ownerCompressed, OWNER.formattedPrivateKey), "http://x").searchParams.toString();

test("no paging param serves the LEGACY bare array of the whole feed", async () => {
  const ledger = await bootedLedger();
  const res = call(ledger, authQuery());
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.body), "the deployed wallet parses an ARRAY — this must not become an envelope");
  assert.equal((res.body as HistoryItem[]).length, FEED_SIZE);
  assert.match(res.headers?.["x-bongtu-auth"] ?? "", /ENFORCED/);
});

test("limit and before serve the { items, nextBefore } envelope", async () => {
  const ledger = await bootedLedger();
  const first = call(ledger, `${authQuery()}&limit=10`).body as HistoryPage;
  assert.equal(first.items.length, 10);
  assert.deepEqual(seqs(first.items), [136, 135, 134, 133, 132, 131, 130, 129, 128, 127]);
  assert.equal(first.nextBefore, 127, "the cursor is the LAST served seq, and it is exclusive");

  const second = call(ledger, `${authQuery()}&limit=10&before=${first.nextBefore}`).body as HistoryPage;
  assert.equal(second.items[0].seq, 126, "the next page starts strictly below the cursor");

  // `before` alone opts into the envelope too, at the default page size.
  const defaulted = call(ledger, `${authQuery()}&before=50`).body as HistoryPage;
  assert.equal(defaulted.items.length, DEFAULT_LIMIT);
  assert.equal(defaulted.items[0].seq, 49);
});

test("nextBefore is null exactly when the feed is exhausted", async () => {
  const ledger = await bootedLedger(5);
  const short = call(ledger, `${authQuery()}&limit=10`).body as HistoryPage;
  assert.equal(short.items.length, 5);
  assert.equal(short.nextBefore, null, "a SHORT page means there is nothing left to ask for");

  // A page that is exactly full still hands back a cursor — the server cannot know
  // the feed ended, and the caller finds out from the empty page that follows.
  const exact = call(ledger, `${authQuery()}&limit=5`).body as HistoryPage;
  assert.equal(exact.nextBefore, 0);
  const beyond = call(ledger, `${authQuery()}&limit=5&before=0`).body as HistoryPage;
  assert.deepEqual(beyond.items, []);
  assert.equal(beyond.nextBefore, null);
});

test("garbage paging params are 400s, and the cap is enforced", async () => {
  const ledger = await bootedLedger();
  // Empty, signed, spaced and hex forms are all rejected — `Number()` would have
  // read them as 0, 5 and 16 and served a page nobody asked for.
  for (const q of ["limit=abc", "limit=0", "limit=-5", "limit=1.5", `limit=${MAX_LIMIT + 1}`, "limit=", "limit=%205"]) {
    assert.equal(call(ledger, `${authQuery()}&${q}`).status, 400, q);
  }
  for (const q of ["before=abc", "before=-1", "before=2.5", "before=", "before=0x10", "before=1e3"]) {
    assert.equal(call(ledger, `${authQuery()}&${q}`).status, 400, q);
  }
  assert.equal(call(ledger, `${authQuery()}&limit=${MAX_LIMIT}`).status, 200, "the cap itself is allowed");
});

test("auth still runs before anything paging-related", async () => {
  const ledger = await bootedLedger();
  // An unauthenticated request is denied on its own terms — a bad `limit` riding
  // along must not turn a 401 into a 400 that reveals the request got further.
  assert.equal(call(ledger, `owner=${ownerCompressed}&limit=abc`).status, 400, "no proof at all is the 400 it always was");
  const stale = new URL(
    buildNotesUrl("http://x", ownerCompressed, STRANGER.formattedPrivateKey),
    "http://x",
  ).searchParams.toString();
  assert.equal(call(ledger, `${stale}&limit=999`).status, 401, "wrong-key signature is 401, not a limit 400");
});

test("a paged request still 503s while the arbiter ledger is unbuilt", () => {
  assert.equal(call(null, `${authQuery()}&limit=10`).status, 503);
});
