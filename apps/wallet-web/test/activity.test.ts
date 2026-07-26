// Headless gates for the PURE activity day-grouping (src/lib/activity.ts) the card
// list renders: local-day buckets labeled Today / Yesterday / locale date, newest day
// first and newest item first within a day, empty feed stays empty. `now` is injected
// for deterministic labels.

import { test } from "node:test";
import assert from "node:assert/strict";

import { groupByDay } from "../src/lib/activity.js";
import type { HistoryItem } from "../src/lib/indexerClient.js";

// A fixed local "now": 2026-07-26 15:00 local time.
const NOW = new Date(2026, 6, 26, 15, 0, 0).getTime();

function item(seq: number, whenMs: number, kind: HistoryItem["kind"] = "received"): HistoryItem {
  return {
    kind,
    counterparty: null,
    amount: "1000000000000000000",
    txHash: `0x${seq.toString(16).padStart(4, "0")}`,
    blockTimestamp: Math.floor(whenMs / 1000),
    seq,
  };
}

test("groupByDay: empty feed returns no groups", () => {
  assert.deepEqual(groupByDay([], NOW), []);
});

test("groupByDay buckets into Today / Yesterday / locale date", () => {
  const today = new Date(2026, 6, 26, 9, 30).getTime();
  const yesterday = new Date(2026, 6, 25, 23, 59).getTime();
  const older = new Date(2026, 6, 20, 12, 0).getTime();
  const groups = groupByDay([item(3, today), item(2, yesterday), item(1, older)], NOW);

  assert.equal(groups.length, 3);
  assert.equal(groups[0].label, "Today");
  assert.equal(groups[1].label, "Yesterday");
  // older days use a locale date, never Today/Yesterday.
  assert.notEqual(groups[2].label, "Today");
  assert.notEqual(groups[2].label, "Yesterday");
  assert.equal(groups[2].label, new Date(2026, 6, 20).toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  }));
  assert.deepEqual(groups.map((g) => g.items.length), [1, 1, 1]);
});

test("groupByDay: newest day first, newest item first within a day", () => {
  const d = (h: number, m: number): number => new Date(2026, 6, 26, h, m).getTime();
  const yest = new Date(2026, 6, 25, 10, 0).getTime();
  // deliberately shuffled input — grouping must not depend on feed order.
  const groups = groupByDay([item(1, d(8, 0)), item(4, yest), item(3, d(14, 30)), item(2, d(9, 15))], NOW);

  assert.equal(groups.length, 2);
  assert.equal(groups[0].label, "Today");
  assert.deepEqual(groups[0].items.map((i) => i.seq), [3, 2, 1]); // newest first
  assert.equal(groups[1].label, "Yesterday");
  assert.deepEqual(groups[1].items.map((i) => i.seq), [4]);
  assert.ok(groups[0].dayStart > groups[1].dayStart, "days ordered newest first");
});

test("groupByDay: same-timestamp items fall back to seq desc", () => {
  const t = new Date(2026, 6, 26, 12, 0).getTime();
  const groups = groupByDay([item(1, t), item(2, t)], NOW);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].items.map((i) => i.seq), [2, 1]);
});

test("groupByDay: a day boundary at local midnight splits buckets", () => {
  const beforeMidnight = new Date(2026, 6, 25, 23, 59, 59).getTime();
  const afterMidnight = new Date(2026, 6, 26, 0, 0, 1).getTime();
  const groups = groupByDay([item(2, afterMidnight), item(1, beforeMidnight)], NOW);
  assert.equal(groups.length, 2);
  assert.equal(groups[0].label, "Today");
  assert.equal(groups[1].label, "Yesterday");
});
