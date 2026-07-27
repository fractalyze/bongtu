// Headless gates for the refresh policy + post-action poller (src/lib/refresh.ts).
//
//   (1) PREDICATE — actionReflected accepts on: the tx in history, a longer
//       history, a changed note set (created/spent); rejects an unchanged state.
//   (2) LOOP — pollForAction stops the moment a snapshot reflects the action,
//       caps out at ~capMs/intervalMs attempts, skips failing loads, and always
//       returns the last good snapshot.
//   (3) POLICY — a tokenless session never issues a doomed token read, and a 401
//       from a token read is classified as a dead login rather than a retryable
//       indexer error.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  actionReflected,
  classifyReadFailure,
  pollForAction,
  refreshPlan,
  EXPIRED_MESSAGE,
  RECONNECT_NOTICE,
  type OwnerSnapshot,
} from "../src/lib/refresh.js";
import type { OwnerNote, HistoryItem } from "../src/lib/indexerClient.js";

const note = (commitment: string, spent: boolean): OwnerNote => ({
  owner: ["1", "2"],
  value: "100",
  salt: "3",
  leafIndex: 0,
  commitment,
  txHash: "0xold",
  spent,
});
const hist = (txHash: string, seq: number): HistoryItem => ({
  kind: "deposit",
  counterparty: null,
  amount: "100",
  txHash,
  blockTimestamp: 1,
  seq,
});

const PRE: OwnerSnapshot = { notes: [note("11", false)], history: [hist("0xold", 1)] };

// ============================ (1) PREDICATE ==================================

test("actionReflected: unchanged state is NOT reflected", () => {
  assert.equal(actionReflected(PRE, { notes: [note("11", false)], history: [hist("0xold", 1)] }, "0xNEW"), false);
});

test("actionReflected accepts each sufficient signal", () => {
  // the action's tx lands in history (case-insensitive hash match)
  assert.equal(
    actionReflected(PRE, { notes: PRE.notes, history: [hist("0xNeW", 2), hist("0xold", 1)] }, "0xnew"),
    true,
  );
  // history grew (even under a different wrapper hash)
  assert.equal(
    actionReflected(PRE, { notes: PRE.notes, history: [hist("0xother", 2), hist("0xold", 1)] }, "0xnew"),
    true,
  );
  // a note was created
  assert.equal(
    actionReflected(PRE, { notes: [note("11", false), note("22", false)], history: PRE.history }, "0xnew"),
    true,
  );
  // a note flipped to spent
  assert.equal(
    actionReflected(PRE, { notes: [note("11", true)], history: PRE.history }, "0xnew"),
    true,
  );
});

// ============================ (2) LOOP =======================================

const instantSleep = async (): Promise<void> => {};

test("pollForAction stops at the first reflecting snapshot", async () => {
  let calls = 0;
  const snapshots: OwnerSnapshot[] = [
    PRE, // still stale
    PRE, // still stale
    { notes: [note("11", true)], history: [hist("0xnew", 2), hist("0xold", 1)] }, // landed
  ];
  const load = async (): Promise<OwnerSnapshot> => snapshots[Math.min(calls++, snapshots.length - 1)];
  const res = await pollForAction(load, PRE, "0xnew", { intervalMs: 10, capMs: 1000, sleep: instantSleep });
  assert.equal(res.landed, true);
  assert.equal(calls, 3, "polling stops the moment the action is reflected");
  assert.ok(res.last && res.last.history[0].txHash === "0xnew");
});

test("pollForAction caps out on a never-reflecting indexer, returning the last snapshot", async () => {
  let calls = 0;
  const load = async (): Promise<OwnerSnapshot> => {
    calls++;
    return PRE;
  };
  const res = await pollForAction(load, PRE, "0xnew", { intervalMs: 3000, capMs: 30000, sleep: instantSleep });
  assert.equal(res.landed, false);
  assert.equal(calls, 10, "cap/interval bounds the attempts (30s / 3s = 10)");
  assert.deepEqual(res.last, PRE, "the last good snapshot is still returned");
});

test("pollForAction skips failing loads and can still land afterwards", async () => {
  let calls = 0;
  const landedSnap: OwnerSnapshot = { notes: PRE.notes, history: [hist("0xnew", 2), hist("0xold", 1)] };
  const load = async (): Promise<OwnerSnapshot> => {
    calls++;
    if (calls < 3) throw new Error("indexer hiccup");
    return landedSnap;
  };
  const res = await pollForAction(load, PRE, "0xnew", { intervalMs: 10, capMs: 1000, sleep: instantSleep });
  assert.equal(res.landed, true);
  assert.equal(calls, 3);
});

test("pollForAction returns last:null when every poll errored", async () => {
  const load = async (): Promise<OwnerSnapshot> => {
    throw new Error("down");
  };
  const res = await pollForAction(load, PRE, "0xnew", { intervalMs: 10, capMs: 50, sleep: instantSleep });
  assert.equal(res.landed, false);
  assert.equal(res.last, null);
});

// ============================ (3) POLICY =====================================

test("refreshPlan: a token reads, a tokenless session only gets a notice", () => {
  assert.deepEqual(refreshPlan({ token: "v1.abc.123.def" }), { kind: "read" });
  // The tokenless fallback session (the indexer had no /auth) has nothing to
  // authenticate with — issuing the read anyway would 400/401 and the error path
  // would wipe the balance that same session just loaded with its key.
  assert.deepEqual(refreshPlan({ token: "" }), { kind: "notice", message: RECONNECT_NOTICE });
  assert.deepEqual(refreshPlan(null), { kind: "notice", message: RECONNECT_NOTICE });
});

test("classifyReadFailure: 401 is a dead login, everything else is retryable", () => {
  const url = "http://localhost:8600";
  const failure = classifyReadFailure(new Error(`${url}/notes -> 401: view token invalid or expired`), url);
  assert.deepEqual(failure, { kind: "expired", message: EXPIRED_MESSAGE });

  // A public-mode indexer has no /notes at all — that is a wrong-indexer problem,
  // not a dead token, so the session survives and Retry stays meaningful.
  const notFound = classifyReadFailure(new Error(`${url}/notes -> 404: not found`), url);
  assert.equal(notFound.kind, "error");
  const forbidden = classifyReadFailure(new Error(`${url}/notes -> 403: nope`), url);
  assert.equal(forbidden.kind, "error");

  // Transport failures name the URL so the Settings field is the obvious next stop.
  const offline = classifyReadFailure(new TypeError("Failed to fetch"), url);
  assert.equal(offline.kind, "error");
  assert.match(offline.message, /http:\/\/localhost:8600/);
  assert.match(offline.message, /Failed to fetch/);

  // Non-Error throws must not crash the classifier.
  assert.equal(classifyReadFailure("boom", url).kind, "error");
});
