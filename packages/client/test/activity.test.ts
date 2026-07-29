// Headless gates for the PURE /history row mapping (src/activity.ts) the
// activity feed keys its copy and amount sign on. Locked policy under test:
//
//   (1) every wire HistoryKind has a verb, in plain words (no note/UTXO jargon);
//   (2) DIRECTION — received/deposit are "in" (+, green), sent/withdraw are
//       "out" (-). A self-send is a sent+received pair, so it renders as a
//       matched -X / +X that nets to zero;
//   (3) a row whose kind this bundle predates (e.g. a 'self' row stored before
//       the pair replaced it) falls back to neutral — never a gain or a loss;
//   (4) PAGING — "Load more" appends the next page in wire order and drops rows
//       the feed already holds, so a refresh landing between pages cannot double
//       a row. (The reset half — a refresh REPLACING the feed — is gated on
//       loadOwnerSnapshot in refresh.test.ts, where the snapshot is built.)

import { test } from "node:test";
import assert from "node:assert/strict";

import { ACTIVITY_VERB, activityDirection, appendHistoryPage } from "../src/activity.js";
import type { HistoryItem, HistoryKind } from "../src/indexerClient.js";

const KINDS: HistoryKind[] = ["received", "sent", "withdraw", "deposit"];

test("every /history kind has a plain-words verb", () => {
  for (const k of KINDS) {
    const verb = ACTIVITY_VERB[k];
    assert.ok(typeof verb === "string" && verb.length > 0, `verb missing for kind "${k}"`);
    assert.ok(!/note|utxo|consolidat|commitment/i.test(verb), `jargon in verb for "${k}": ${verb}`);
  }
});

test("a self-send pair nets to zero in the rendered direction", () => {
  // Both rows carry the same amount, and the signs cancel — which is what makes
  // the pair a truthful replacement for the single neutral 'self' row.
  assert.equal(activityDirection("sent"), "out");
  assert.equal(activityDirection("received"), "in");
});

test("direction: in for received/deposit, out for sent/withdraw", () => {
  assert.equal(activityDirection("received"), "in");
  assert.equal(activityDirection("deposit"), "in");
  assert.equal(activityDirection("sent"), "out");
  assert.equal(activityDirection("withdraw"), "out");
});

// ============================ (4) PAGING =====================================

const row = (seq: number): HistoryItem => ({
  kind: "received",
  counterparty: null,
  amount: String(seq),
  txHash: `0x${seq}`,
  blockTimestamp: 1_700_000_000 + seq,
  seq,
});
const seqs = (items: HistoryItem[]): number[] => items.map((i) => i.seq);

test("a next page appends after what is on screen, in wire order", () => {
  const onScreen = [row(9), row(8), row(7)];
  const next = [row(6), row(5)];
  assert.deepEqual(seqs(appendHistoryPage(onScreen, next)), [9, 8, 7, 6, 5]);
  // …and the input is not mutated: React state must be replaced, not edited.
  assert.deepEqual(seqs(onScreen), [9, 8, 7]);
});

test("a page overlapping the feed cannot duplicate a row", () => {
  // The race this exists for: a refresh replaced the feed with a fresh first page
  // while the next-page request (cursor taken against the OLD feed) was in flight,
  // so the page comes back holding rows the new head already has.
  const refreshed = [row(11), row(10), row(9), row(8), row(7)];
  const inFlight = [row(8), row(7), row(6), row(5)];
  const merged = appendHistoryPage(refreshed, inFlight);
  assert.deepEqual(seqs(merged), [11, 10, 9, 8, 7, 6, 5]);
  assert.equal(new Set(seqs(merged)).size, merged.length, "every seq appears exactly once");
});

test("an empty page and a fully-overlapping page both leave the feed alone", () => {
  const onScreen = [row(3), row(2)];
  assert.deepEqual(seqs(appendHistoryPage(onScreen, [])), [3, 2]);
  assert.deepEqual(seqs(appendHistoryPage(onScreen, [row(3), row(2)])), [3, 2]);
});

test("a kind this bundle does not know renders neutral, not as a gain or a loss", () => {
  // The cast is the point: a stored row can carry a kind the wire type no longer
  // has (the retired 'self'), and the feed must still render it harmlessly.
  assert.equal(activityDirection("self" as HistoryKind), "none");
  assert.equal(ACTIVITY_VERB["self" as HistoryKind], undefined); // ActivityList falls back to the raw kind
});
