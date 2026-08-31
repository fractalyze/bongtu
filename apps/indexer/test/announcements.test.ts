// Headless gate for the /announcements feed, at the three seams the route now
// only composes:
//
//   1. STORE PROJECTION — InMemoryStore.announcements (the same read model
//      PostgresStore wraps): announcement-carrying withdraws only, cursor
//      paging, projection fields.
//   2. LEDGER ATTRIBUTION — PostgresLedger.withdrawTxHashesOf, driven through
//      the ledger's OWN apply()/deriveOp path with REAL encrypted authority
//      envelopes (the ingest.test.ts recipe: poseidonEncrypt to the arbiter,
//      no SQL — apply/reads never touch the pool).
//   3. ROUTE — the public cursor path, the arbiter per-owner slice behind the
//      shared read-auth, and the mode fences. Store entries are built through
//      the REAL InMemoryStore; the ledger is a stub of withdrawTxHashesOf —
//      composition, not attribution, is under test here (the ingest attach
//      itself is exercised by the conformance gate).

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Pool } from "pg";

import { deriveKeypair, commitment, poseidonEncrypt, ecdhSharedSecret } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { buildAuthorityPlaintext, type EnvNote } from "@bongtu/core/envelope";
import { notesAuthMessage, signNotesAuth, packSignature } from "@bongtu/core/eddsa";
import { InMemoryStore } from "../src/store.js";
import { MirrorTree } from "../src/tree.js";
import { PostgresLedger } from "../src/postgres.js";
import type { OpEnvelope } from "../src/ledger.js";
import { announcements } from "../src/api/routes/announcements.js";
import type { Indexer } from "../src/ingest.js";
import type { RouteContext, RouteResult } from "../src/api/router.js";

const OWNER = deriveKeypair(123456789123456789n);
const OTHER = deriveKeypair(987654321987654321n);
const ownerCompressed = packPubkey(OWNER.publicKey);

function seededStore(): InMemoryStore {
  const store = new InMemoryStore();
  for (const i of Array(3).keys()) {
    const e = store.addEvent({
      txHash: `0xw${i}`, blockNumber: 100 + i, logIndex: 0,
      kind: "withdraw", epoch: null, ecdhPublicKey: null, encryptionNonce: null,
      slices: [], ciphertext: [],
    });
    e!.announcement = {
      recipient: `0x${String(i).repeat(40)}`,
      ephemeralPub: "0x" + String(i).repeat(64),
      viewTag: i,
    };
  }
  // A withdraw WITHOUT an announcement (pre-upgrade history, or a plain
  // withdraw — the ingest's core-predicate gate attaches nothing for the
  // zero-sentinel pair) and a non-withdraw entry: neither may appear in the feed.
  store.addEvent({
    txHash: "0xold", blockNumber: 50, logIndex: 0,
    kind: "withdraw", epoch: null, ecdhPublicKey: null, encryptionNonce: null,
    slices: [], ciphertext: [],
  });
  store.addEvent({
    txHash: "0xdep", blockNumber: 51, logIndex: 0,
    kind: "deposit", epoch: 0, ecdhPublicKey: ["1", "2"], encryptionNonce: "3",
    slices: [], ciphertext: [],
  });
  return store;
}

// ============================ (1) STORE PROJECTION ===========================

test("store.announcements serves only announcement-carrying withdraws, fully projected", () => {
  const store = seededStore();
  const all = store.announcements();
  assert.equal(all.length, 3, "0xold (no announcement) and 0xdep (non-withdraw) excluded");
  assert.deepEqual(all.map((a) => a.txHash), ["0xw0", "0xw1", "0xw2"]);
  // The projection carries the feed identity AND the whole announcement — a
  // dropped field here silently breaks the wallet's stealth scan.
  assert.deepEqual(all[1], {
    seq: all[1].seq,
    txHash: "0xw1",
    blockNumber: 101,
    recipient: "0x" + "1".repeat(40),
    ephemeralPub: "0x" + "1".repeat(64),
    viewTag: 1,
  });
});

test("store.announcements pages by seq cursor and caps by limit", () => {
  const store = seededStore();
  const all = store.announcements();
  assert.deepEqual(store.announcements(all[0].seq, 1).map((a) => a.txHash), ["0xw1"]);
  assert.deepEqual(store.announcements(all[0].seq).map((a) => a.txHash), ["0xw1", "0xw2"]);
  assert.deepEqual(store.announcements(all[2].seq), [], "cursor at the head leaves nothing");
  assert.equal(store.announcements(-1, 500).length, 3, "an oversized limit returns what exists");
});

// ============================ (2) LEDGER ATTRIBUTION =========================

// A real arbiter-mode ledger seeded through its own apply()/deriveOp path: the
// envelopes below are genuine poseidonEncrypt bytes keyed to ARB, and the
// outputLeaves carry the matching commitments so every cross-check passes.
// apply/notesOf/historyOf/withdrawTxHashesOf never touch SQL, so a never-used
// dummy pool is safe (the ingest.test.ts convention).
const ARB = deriveKeypair(424242424242424242424242n);
const DUMMY_PG_POOL = null as unknown as Pool;
const H = 8;
const B = 4;

const envNote = (owner: Keypair, value: bigint, salt: bigint): EnvNote => ({ owner: owner.publicKey, value, salt });
const pub2 = (k: Keypair): [bigint, bigint] => [k.publicKey[0], k.publicKey[1]];

function sealed(
  kind: "withdraw" | "deposit",
  txHash: string,
  env: { inputs: EnvNote[]; outputs: EnvNote[] },
  eph: bigint,
  nonce: bigint,
  firstLeaf: number,
): OpEnvelope {
  const plain = buildAuthorityPlaintext(kind, env);
  return {
    kind, txHash, logIndex: 0, blockTimestamp: 1_700_000_000,
    ecdhPublicKey: pub2(deriveKeypair(eph)),
    nonce,
    authorityCt: poseidonEncrypt(plain, ecdhSharedSecret(eph, ARB.publicKey), nonce),
    kem: null,
    outputLeaves: env.outputs.map((o, i) => ({
      leafIndex: firstLeaf + i,
      commitment: commitment(o.value, o.salt, o.owner),
    })),
  };
}

function appliedLedger(): PostgresLedger {
  const ledger = new PostgresLedger(DUMMY_PG_POOL, ARB.formattedPrivateKey, null, B, new MirrorTree(H, B));
  // OWNER: a deposit (non-withdraw history), then a real withdraw (40 in, 2 change).
  ledger.apply(sealed("deposit", "0xdep",
    { inputs: [], outputs: [envNote(OWNER, 40n, 1001n), envNote(OWNER, 0n, 1002n)] },
    510000000000000000001n, 11n, 0));
  ledger.apply(sealed("withdraw", "0xwd-owner",
    { inputs: [envNote(OWNER, 40n, 1001n), envNote(OWNER, 0n, 1002n)], outputs: [envNote(OWNER, 2n, 1003n)] },
    520000000000000000001n, 22n, 2));
  // OTHER's withdraw must never attribute to OWNER.
  ledger.apply(sealed("withdraw", "0xwd-other",
    { inputs: [envNote(OTHER, 7n, 2001n), envNote(OTHER, 0n, 2002n)], outputs: [envNote(OTHER, 0n, 2003n)] },
    530000000000000000001n, 33n, 3));
  // A withdraw that unshields NOTHING (change == inputs) derives no history row,
  // so it must not attribute either — the set follows the history rows, not the
  // op kind.
  ledger.apply(sealed("withdraw", "0xwd-zero",
    { inputs: [envNote(OWNER, 5n, 3001n), envNote(OWNER, 0n, 3002n)], outputs: [envNote(OWNER, 5n, 3003n)] },
    540000000000000000001n, 44n, 4));
  return ledger;
}

test("withdrawTxHashesOf attributes exactly the owner's unshielding withdraws", () => {
  const ledger = appliedLedger();
  assert.deepEqual(ledger.withdrawTxHashesOf(OWNER.publicKey[0], OWNER.publicKey[1]), new Set(["0xwd-owner"]),
    "the deposit, the other owner's withdraw, and the zero-unshield withdraw all stay out");
  assert.deepEqual(ledger.withdrawTxHashesOf(OTHER.publicKey[0], OTHER.publicKey[1]), new Set(["0xwd-other"]));
  const stranger = deriveKeypair(555555555555555555n);
  assert.deepEqual(ledger.withdrawTxHashesOf(stranger.publicKey[0], stranger.publicKey[1]), new Set());
});

test("withdrawTxHashesOf is derived from the SAME rows historyOf serves", () => {
  const ledger = appliedLedger();
  for (const kp of [OWNER, OTHER]) {
    const fromHistory = new Set(
      ledger.historyOf(kp.publicKey[0], kp.publicKey[1])
        .filter((h) => h.kind === "withdraw")
        .map((h) => h.txHash),
    );
    assert.deepEqual(ledger.withdrawTxHashesOf(kp.publicKey[0], kp.publicKey[1]), fromHistory);
  }
});

// ============================ (3) ROUTE ======================================

function makeIx(arbiter: boolean, ownerTxs: string[] = []): Indexer {
  return {
    arbiterMode: arbiter,
    store: seededStore(),
    ledger: arbiter
      ? {
          withdrawTxHashesOf: (x: bigint, y: bigint) =>
            x === OWNER.publicKey[0] && y === OWNER.publicKey[1] ? new Set(ownerTxs) : new Set<string>(),
        }
      : null,
  } as unknown as Indexer;
}

function call(ix: Indexer, query: string): RouteResult {
  const ctx: RouteContext = { ix, tokens: null, params: [], query: new URLSearchParams(query) };
  return announcements.handle(ctx) as RouteResult;
}

const signedQ = (): string => {
  const ts = Math.floor(Date.now() / 1000);
  const sig = packSignature(signNotesAuth(OWNER.formattedPrivateKey, notesAuthMessage(OWNER.publicKey, ts)));
  return `owner=${encodeURIComponent(ownerCompressed)}&ts=${ts}&sig=${sig}`;
};

test("public feed serves only announcement-carrying withdraws, cursor-paged", () => {
  const ix = makeIx(false);
  const r = call(ix, "");
  assert.equal(r.status, 200);
  const body = r.body as { seq: number; txHash: string; viewTag: number }[];
  assert.equal(body.length, 3); // 0xold (no announcement) and 0xdep excluded
  assert.deepEqual(body.map((a) => a.txHash), ["0xw0", "0xw1", "0xw2"]);

  const paged = call(ix, `cursor=${body[0].seq}&limit=1`).body as { txHash: string }[];
  assert.deepEqual(paged.map((a) => a.txHash), ["0xw1"]);
});

test("owner slice: arbiter mode + valid signature returns only the owner's txs", () => {
  const ix = makeIx(true, ["0xw1"]);
  const r = call(ix, signedQ());
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const body = r.body as { txHash: string; viewTag: number }[];
  assert.deepEqual(body.map((a) => a.txHash), ["0xw1"]);
  assert.match((r.headers ?? {})["x-bongtu-auth"] ?? "", /ENFORCED/);
});

test("owner slice: a wrong-key signature is denied before any ledger read", () => {
  const ix = makeIx(true, ["0xw1"]);
  const ts = Math.floor(Date.now() / 1000);
  const sig = packSignature(signNotesAuth(OTHER.formattedPrivateKey, notesAuthMessage(OWNER.publicKey, ts)));
  const r = call(ix, `owner=${encodeURIComponent(ownerCompressed)}&ts=${ts}&sig=${sig}`);
  assert.equal(r.status, 401);
});

test("owner slice does not exist on a public-mode indexer", () => {
  const r = call(makeIx(false), signedQ());
  assert.equal(r.status, 404);
});

test("malformed cursor/limit is the caller's 400", () => {
  assert.equal(call(makeIx(false), "cursor=abc").status, 400);
  assert.equal(call(makeIx(false), "limit=0").status, 400);
});
