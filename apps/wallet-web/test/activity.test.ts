// Headless gates for the PURE /history row mapping (src/lib/activity.ts) the
// activity feed keys its copy and amount sign on. Locked policy under test:
//
//   (1) every wire HistoryKind has a verb, in plain words (no note/UTXO jargon);
//   (2) DIRECTION — received/deposit are "in" (+, green), sent/withdraw are
//       "out" (-). A self-send is a sent+received pair, so it renders as a
//       matched -X / +X that nets to zero;
//   (3) a row whose kind this bundle predates (e.g. a 'self' row stored before
//       the pair replaced it) falls back to neutral — never a gain or a loss.

import { test } from "node:test";
import assert from "node:assert/strict";

import { ACTIVITY_VERB, activityDirection } from "../src/lib/activity.js";
import type { HistoryKind } from "../src/lib/indexerClient.js";

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

test("a kind this bundle does not know renders neutral, not as a gain or a loss", () => {
  // The cast is the point: a stored row can carry a kind the wire type no longer
  // has (the retired 'self'), and the feed must still render it harmlessly.
  assert.equal(activityDirection("self" as HistoryKind), "none");
  assert.equal(ACTIVITY_VERB["self" as HistoryKind], undefined); // ActivityList falls back to the raw kind
});
