// Headless gates for the PURE /history row mapping (src/lib/activity.ts) the
// activity feed keys its copy and amount sign on. Locked policy under test:
//
//   (1) every wire HistoryKind — including "self" (a pure self-send, U-Y2 /
//       fractalyze/bongtu#1) — has a verb, in plain words (no note/UTXO jargon);
//   (2) DIRECTION — received/deposit are "in" (+, green), sent/withdraw are
//       "out" (-), and "self" is "none": the balance did not change, so the
//       amount must render unsigned, never as a gain or a loss.

import { test } from "node:test";
import assert from "node:assert/strict";

import { ACTIVITY_VERB, activityDirection } from "../src/lib/activity.js";
import type { HistoryKind } from "../src/lib/indexerClient.js";

const KINDS: HistoryKind[] = ["received", "sent", "withdraw", "deposit", "self"];

test("every /history kind has a plain-words verb", () => {
  for (const k of KINDS) {
    const verb = ACTIVITY_VERB[k];
    assert.ok(typeof verb === "string" && verb.length > 0, `verb missing for kind "${k}"`);
    assert.ok(!/note|utxo|consolidat|commitment/i.test(verb), `jargon in verb for "${k}": ${verb}`);
  }
});

test("self-send reads as an internal move, not a payment", () => {
  assert.equal(ACTIVITY_VERB.self, "Moved within your balance");
});

test("direction: in for received/deposit, out for sent/withdraw, none for self", () => {
  assert.equal(activityDirection("received"), "in");
  assert.equal(activityDirection("deposit"), "in");
  assert.equal(activityDirection("sent"), "out");
  assert.equal(activityDirection("withdraw"), "out");
  assert.equal(activityDirection("self"), "none");
});
