// Headless gates for the ScanSession (scan/session.ts, issue #53): the session
// drives the whole self-scan round-trip over a fake store + fake io — no app,
// no React, no network. Coverage:
//
//   (1) RESUMABILITY, session-owned: one pass persists cursor + notes +
//       pending TOGETHER (the run.ts contract), resumes memory-first, and a
//       fresh session over the same store resumes from the persisted cursor;
//   (2) LOCKED / identity gate: no feed IO without the consumer identity — the
//       previous state is served untouched under the right notice;
//   (3) NOTICE PRECEDENCE (one home: scanNotice): pending beats locked, locked
//       beats nothing, an unlocked fully-delivered scan earns no strip;
//   (4) FORGET-OWNER vs sign-out vs detach: forgetOwner clears the stamped
//       owner's stored row; end() drops memory + stamp but keeps the row;
//       detach() keeps the stamp so a later clean-device forget still clears.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { FeedEvent } from "@bongtu/core/indexerApi";
import { deriveIdentityFromSignature, type WalletIdentity } from "@bongtu/client/derive";
import {
  EMPTY_SCAN_STATE,
  SELF_SCAN_LOCKED_NOTICE,
  SELF_SCAN_PENDING_NOTICE,
  ScanSession,
  scanNotice,
  type PendingDiscovery,
  type ScanNote,
  type ScanStateStore,
  type SelfScanIo,
  type SelfScanState,
} from "@bongtu/client/selfscan";

// ---- deterministic material -------------------------------------------------

const ME = deriveIdentityFromSignature("0x" + "a1".repeat(32) + "b2".repeat(32) + "1c");
const OWNER = ME.compressedPubkey;

/** A note an earlier pass discovered — resume must not lose it. */
const NOTE: ScanNote = {
  value: "600",
  salt: "1",
  leafIndex: 0,
  commitment: "11",
  nullifier: "22",
  txHash: "0xaa",
  spent: false,
  seq: 1,
  kind: "depositPriv",
  family: "consumer",
};

/** An unresolved batch — resume must keep carrying (and re-reading) it. */
const PEND: PendingDiscovery = { seq: 3, txHash: "0xbb", batchId: 7, status: "pending" };

const PREV: SelfScanState = {
  v: 1,
  cursor: 2,
  scannedNextLeafIndex: 1,
  notes: [NOTE],
  pending: [PEND],
};

const PREV_NO_PENDING: SelfScanState = { ...PREV, pending: [] };

/** A feed entry the pass can cursor past but not open (no receiver material) —
 *  advances the cursor without any crypto. */
const EV5: FeedEvent = {
  seq: 5,
  txHash: "0xcc",
  blockNumber: 5,
  kind: "depositPriv",
  epoch: null,
  ecdhPublicKey: null,
  encryptionNonce: null,
  slices: [],
  ciphertext: [],
};

// ---- fakes ------------------------------------------------------------------

function fakeIo(events: FeedEvent[], nextLeafIndex = 0): {
  io: SelfScanIo;
  calls: { events: number[]; head: number };
} {
  const calls = { events: [] as number[], head: 0 };
  const io: SelfScanIo = {
    events: async (cursor, limit) => {
      calls.events.push(cursor);
      const page = events.filter((e) => e.seq > cursor);
      return limit === undefined ? page : page.slice(0, limit);
    },
    nullifiers: async () => [],
    head: async () => {
      calls.head += 1;
      return { root: "0", nextLeafIndex };
    },
    path: async () => {
      throw new Error("no /path in this feed");
    },
  };
  return { io, calls };
}

function fakeStore(seed?: Record<string, SelfScanState>): {
  rows: Map<string, SelfScanState>;
  calls: { load: string[]; save: string[]; clear: string[] };
  store: ScanStateStore;
} {
  const rows = new Map(Object.entries(seed ?? {}));
  const calls = { load: [] as string[], save: [] as string[], clear: [] as string[] };
  const store: ScanStateStore = {
    load: (o) => {
      calls.load.push(o);
      return rows.get(o) ?? null;
    },
    save: (o, s) => {
      calls.save.push(o);
      rows.set(o, s);
    },
    clear: (o) => {
      calls.clear.push(o);
      rows.delete(o);
    },
  };
  return { rows, calls, store };
}

const HELD = { peek: (): WalletIdentity | null => ME };
const LOCKED = { peek: (): WalletIdentity | null => null };

// ========================= (1) RESUMABILITY ==================================

test("one pass persists cursor + notes + pending TOGETHER, and resumes memory-first", async () => {
  const { store, rows, calls } = fakeStore({ [OWNER]: PREV });
  const { io, calls: ioCalls } = fakeIo([EV5], 7);
  const session = new ScanSession(io, store, HELD);

  const out = await session.scan(OWNER);
  const saved = rows.get(OWNER);
  assert.ok(saved, "the pass wrote the state back through the store seam");
  // The run.ts resumability contract, now session-owned: the advanced cursor,
  // the pre-cursor note, and the still-unresolved pending entry land in the
  // SAME stored row — never a field at a time.
  assert.equal(saved.cursor, 5);
  assert.deepEqual(saved.notes.map((n) => n.commitment), [NOTE.commitment]);
  assert.deepEqual(saved.pending.map((p) => p.seq), [PEND.seq]);
  assert.equal(saved.scannedNextLeafIndex, 7);
  assert.deepEqual(calls.save, [OWNER]);

  // The outcome mirrors exactly what was persisted.
  assert.equal(out.scannedNextLeafIndex, 7);
  assert.equal(out.snapshot.notes.length, 1);
  assert.equal(out.snapshot.notes[0]?.commitment, NOTE.commitment);
  assert.equal(out.snapshot.historyNextBefore, null);
  assert.equal(out.notice, SELF_SCAN_PENDING_NOTICE);
  assert.deepEqual(session.notes().map((n) => n.commitment), [NOTE.commitment]);

  // Memory-first resume: the second pass never re-loads the store, drains the
  // feed from the persisted cursor (5), and re-reads the pending seq (3 - 1).
  const before = ioCalls.events.length;
  await session.scan(OWNER);
  assert.deepEqual(calls.load, [OWNER], "one store load for the whole session");
  assert.deepEqual(ioCalls.events.slice(before), [5, 2]);
});

test("a fresh session over the same store resumes from the persisted cursor (store round-trip)", async () => {
  const { store } = fakeStore({ [OWNER]: PREV });
  const first = new ScanSession(fakeIo([EV5], 7).io, store, HELD);
  await first.scan(OWNER);

  const { io, calls } = fakeIo([EV5], 7);
  const second = new ScanSession(io, store, HELD);
  await second.scan(OWNER);
  // drain from the STORED cursor (5), then the stored pending re-read (3 - 1)
  // — the persisted row carried cursor, notes, and pending together.
  assert.deepEqual(calls.events, [5, 2]);
  assert.deepEqual(second.notes().map((n) => n.commitment), [NOTE.commitment]);
});

test("memory stamped for another owner is never resumed: the per-owner store row decides", async () => {
  const OTHER = deriveIdentityFromSignature("0x" + "c3".repeat(32) + "d4".repeat(32) + "1b");
  const { store } = fakeStore({ [OWNER]: PREV });
  const { io, calls } = fakeIo([], 0);
  const session = new ScanSession(io, store, { peek: () => OTHER });
  await session.scan(OWNER); // stamps OWNER's state in memory
  const before = calls.events.length;
  await session.scan(OTHER.compressedPubkey);
  // The other owner has no stored row: the drain starts from the feed's
  // beginning (EMPTY_SCAN_STATE), not from OWNER's in-memory cursor.
  assert.equal(calls.events[before], EMPTY_SCAN_STATE.cursor);
});

// ==================== (2) LOCKED / IDENTITY GATE =============================

test("a locked wallet serves the previous state untouched: no feed IO, the locked notice", async () => {
  const { store, calls } = fakeStore({ [OWNER]: PREV_NO_PENDING });
  const { io, calls: ioCalls } = fakeIo([EV5], 7);
  const session = new ScanSession(io, store, LOCKED);
  const out = await session.scan(OWNER);
  assert.equal(ioCalls.head, 0, "a locked pass never reads the feed");
  assert.deepEqual(ioCalls.events, []);
  assert.equal(out.notice, SELF_SCAN_LOCKED_NOTICE);
  assert.equal(out.snapshot.notes[0]?.commitment, NOTE.commitment, "the last scan still serves");
  assert.equal(out.scannedNextLeafIndex, PREV_NO_PENDING.scannedNextLeafIndex);
  assert.deepEqual(calls.save, [OWNER], "the unchanged state still round-trips");
});

test("an enterprise-only identity cannot self-scan but is not 'locked': pass skipped, no strip", async () => {
  const enterpriseOnly: WalletIdentity = { keypair: ME.keypair, compressedPubkey: ME.compressedPubkey };
  const { store } = fakeStore({ [OWNER]: PREV_NO_PENDING });
  const { io, calls } = fakeIo([EV5], 7);
  const session = new ScanSession(io, store, { peek: () => enterpriseOnly });
  const out = await session.scan(OWNER);
  assert.deepEqual(calls.events, []);
  assert.equal(out.notice, null);
});

// ======================= (3) NOTICE PRECEDENCE ===============================

test("scanNotice: pending kem delivery wins, then the locked strip, then nothing", () => {
  const withPending: SelfScanState = { ...EMPTY_SCAN_STATE, pending: [PEND] };
  assert.equal(scanNotice(withPending, true), SELF_SCAN_PENDING_NOTICE);
  // pending is the more actionable fact even while locked: no unlock could
  // reveal a note whose kem chunks have not landed.
  assert.equal(scanNotice(withPending, false), SELF_SCAN_PENDING_NOTICE);
  assert.equal(scanNotice(EMPTY_SCAN_STATE, false), SELF_SCAN_LOCKED_NOTICE);
  assert.equal(scanNotice(EMPTY_SCAN_STATE, true), null);
});

test("the session's outcome keeps the precedence: a LOCKED pass over pending still says pending", async () => {
  const { store } = fakeStore({ [OWNER]: PREV });
  const session = new ScanSession(fakeIo([], 0).io, store, LOCKED);
  const out = await session.scan(OWNER);
  assert.equal(out.notice, SELF_SCAN_PENDING_NOTICE);
});

// ================ (4) FORGET-OWNER / SIGN-OUT / DETACH =======================

test("forgetOwner clears the stamped owner's stored row and empties the session", async () => {
  const { store, rows, calls } = fakeStore({ [OWNER]: PREV });
  const session = new ScanSession(fakeIo([EV5], 7).io, store, HELD);
  await session.scan(OWNER);
  session.forgetOwner();
  assert.deepEqual(calls.clear, [OWNER]);
  assert.equal(rows.has(OWNER), false);
  assert.deepEqual(session.notes(), []);
});

test("a plain end() drops memory + stamp but KEEPS the stored row for the next login", async () => {
  const { store, rows, calls } = fakeStore({ [OWNER]: PREV });
  const session = new ScanSession(fakeIo([EV5], 7).io, store, HELD);
  await session.scan(OWNER);
  session.end();
  assert.deepEqual(calls.clear, []);
  assert.ok(rows.has(OWNER), "a plain sign-out keeps the stored scan");
  assert.deepEqual(session.notes(), []);
  // A forget AFTER the stamp died clears nothing — the stamp rule's whole
  // point: a later owner's Disconnect must never clear the previous owner's
  // row through a stale stamp.
  session.forgetOwner();
  assert.deepEqual(calls.clear, []);
  assert.ok(rows.has(OWNER));
  // And the surviving row is what the next pass resumes from.
  await session.scan(OWNER);
  assert.deepEqual(calls.load, [OWNER, OWNER]);
});

test("detach() drops memory only: the stamp still names the row a clean-device forget clears", async () => {
  const { store, rows, calls } = fakeStore({ [OWNER]: PREV });
  const session = new ScanSession(fakeIo([EV5], 7).io, store, HELD);
  await session.scan(OWNER);
  session.detach();
  assert.deepEqual(session.notes(), []);
  session.forgetOwner();
  assert.deepEqual(calls.clear, [OWNER]);
  assert.equal(rows.has(OWNER), false);
});
