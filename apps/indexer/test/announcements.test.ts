// Headless gate for the /announcements feed: the public cursor path, the
// arbiter per-owner slice behind the shared read-auth, and the mode fences.
// Store entries are built through the REAL InMemoryStore (same seq/dedup path
// ingest uses); the ledger is a stub — attribution, not decryption, is under
// test here (the ingest attach itself is exercised by the conformance gate).

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { notesAuthMessage, signNotesAuth, packSignature } from "@bongtu/core/eddsa";
import { InMemoryStore } from "../src/store.js";
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
  // A withdraw WITHOUT an announcement (pre-upgrade history) and a non-withdraw
  // entry: neither may appear in the feed.
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

function makeIx(arbiter: boolean, ownerTxs: string[] = []): Indexer {
  return {
    arbiterMode: arbiter,
    store: seededStore(),
    ledger: arbiter
      ? {
          historyOf: (x: bigint, y: bigint) =>
            x === OWNER.publicKey[0] && y === OWNER.publicKey[1]
              ? ownerTxs.map((txHash, i) => ({ kind: "withdraw", txHash, amount: "1", counterparty: null, blockTimestamp: 1, seq: i }))
              : [],
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
