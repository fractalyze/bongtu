// Interface-level gates for the S5 discovery surface, all driven from ONE shared
// fake-scan world (a SelfScanState the tables reuse — the seam S6's op screens
// will read their world through):
//
//   (1) BALANCE-STATE TABLE — homeView (homeView.ts): loading / zero-after-scan /
//       value / pending / locked / stale, from the same world. The stale row is
//       the partial-coverage honesty: a maxPages-capped run stamps only what it
//       covered, and the dot marks it — never a silently small balance reading
//       "synced".
//   (2) ACTIVITY PRESENTER — presentActivity (activityView.ts): wire order kept,
//       directions, signed amounts, counterparty display forms, time-or-nothing,
//       explorer targets, unknown-kind degradation.
//   (3) GUARD SEQUENCES — accountGuard/forgetDevice (lib/accountGuard.ts):
//       switch → lock + detach (never a sign-out, never a store clear);
//       disconnected → sign-out for WalletConnect only; explicit Disconnect →
//       the clean-device trio.
//   (4) AUTO-REFRESH GATE — autoTickAllowed (lib/refreshGate.ts): a hidden tab
//       runs no pass, a tick never overlaps itself; plus the source pins that
//       App actually wires these seams and reads the lock with peek() only —
//       a background pass must never extend the idle deadline.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { encodeAddress } from "@bongtu/core/pubkey";
import { deriveScanActivity, type PendingDiscovery, type ScanNote, type SelfScanState } from "@bongtu/client/selfscan";
import type { HistoryItem, HistoryKind } from "@bongtu/core/indexerApi";
import { homeView } from "../src/ui/homeView.js";
import { presentActivity, presentActivityRow } from "../src/ui/activityView.js";
import { accountGuard, forgetDevice, WALLET_ENDED_NOTICE } from "../src/lib/accountGuard.js";
import { autoTickAllowed } from "../src/lib/refreshGate.js";
import {
  SELF_SCAN_LOCKED_NOTICE,
  SELF_SCAN_PENDING_NOTICE,
} from "@bongtu/client/selfscan";

// ========================= the ONE shared fake-scan world ====================

const KKRW = 10n ** 18n;

const note = (
  over: Pick<ScanNote, "seq" | "kind" | "txHash"> & Partial<ScanNote> & { kkrw: bigint },
): ScanNote => ({
  value: (over.kkrw * KKRW).toString(),
  salt: "1",
  leafIndex: over.seq,
  commitment: `c-${over.seq}-${over.kkrw}`,
  nullifier: `n-${over.seq}-${over.kkrw}`,
  spent: false,
  family: "consumer",
  ...over,
});

// A lived-in account: a minted deposit (later spent), one incoming transfer
// event carrying TWO of our outputs (the per-event sum), and a withdraw's
// change note. Unspent balance: 600 + 50 + 250 = 900 kKRW.
const WORLD: SelfScanState = {
  v: 1,
  cursor: 7,
  scannedNextLeafIndex: 12,
  notes: [
    note({ seq: 2, kind: "depositPriv", txHash: "0xdep", kkrw: 1000n, spent: true }),
    note({ seq: 5, kind: "transferPriv", txHash: "0xrcv", kkrw: 600n }),
    note({ seq: 5, kind: "transferPriv", txHash: "0xrcv", kkrw: 50n }),
    note({ seq: 7, kind: "withdrawPriv", txHash: "0xwd", kkrw: 250n }),
  ],
  pending: [],
};

const PENDING: PendingDiscovery = { seq: 9, txHash: "0xp", batchId: 4, status: "pending" };
const HEAD_AT = (nextLeafIndex: number) => ({ root: "1", nextLeafIndex });

/** The world's Home view, with per-row overrides. */
const VIEW = (over: Partial<Parameters<typeof homeView>[0]> = {}) =>
  homeView({
    scan: WORLD,
    identityHeld: true,
    loading: false,
    dataError: false,
    head: HEAD_AT(12),
    headErrored: false,
    ...over,
  });

// ========================= (1) BALANCE-STATE TABLE ===========================

test("balance-state table: loading / zero-after-scan / value / pending / locked / stale", () => {
  // LOADING: no completed pass yet — the hero must never fabricate a zero.
  assert.deepEqual(VIEW({ scan: null, loading: true }).hero, { kind: "loading" });
  assert.deepEqual(VIEW({ scan: null }).hero, { kind: "unloaded" });
  assert.equal(VIEW({ scan: null, loading: true }).strip, null, "no strip before a pass lands");

  // ZERO-AFTER-SCAN: a completed pass that found nothing IS zero — the truth.
  const zero = VIEW({ scan: { ...WORLD, notes: [] } });
  assert.deepEqual(zero.hero, { kind: "amount", text: "0" });

  // VALUE: unspent sum only — the spent deposit drops out (1000 spent; 900 left).
  const value = VIEW();
  assert.deepEqual(value.hero, { kind: "amount", text: "900" });
  assert.equal(value.strip, null, "an unlocked, fully-delivered scan needs no strip");
  assert.equal(value.dot, "synced");

  // PENDING: kem chunks in flight — the calm strip, the number stays on screen.
  const pending = VIEW({ scan: { ...WORLD, pending: [PENDING] } });
  assert.equal(pending.strip, SELF_SCAN_PENDING_NOTICE);
  assert.deepEqual(pending.hero, { kind: "amount", text: "900" });

  // LOCKED: the last snapshot serves under the calm notice — never blanked.
  const locked = VIEW({ identityHeld: false });
  assert.equal(locked.strip, SELF_SCAN_LOCKED_NOTICE);
  assert.deepEqual(locked.hero, { kind: "amount", text: "900" });
  assert.equal(locked.dot, "synced", "locked is a key state, not a sync state");

  // STALE: coverage stopped short of /head (the maxPages-capped stamp) — the
  // dot marks it while the number stays: an honest partial balance, never a
  // silently small one reading synced.
  const stale = VIEW({ head: HEAD_AT(20) });
  assert.equal(stale.dot, "stale");
  assert.deepEqual(stale.hero, { kind: "amount", text: "900" });
});

// ========================= (2) ACTIVITY PRESENTER ============================

test("activity presenter over the world's derived feed: order, directions, signed amounts", () => {
  const rows = presentActivity(deriveScanActivity(WORLD.notes), "https://scan.test/");

  // Newest-first straight from the derivation, one row per feed event.
  assert.deepEqual(rows.map((r) => r.key), ["7-0xwd", "5-0xrcv", "2-0xdep"]);

  const [wd, rcv, dep] = rows;
  // The withdraw change note reads as the wallet's own withdraw: out, signed -.
  assert.equal(wd.verb, "Withdrawn");
  assert.equal(wd.direction, "out");
  assert.equal(wd.amount, "-250");
  // Two outputs of one event sum into one row: in, signed +.
  assert.equal(rcv.verb, "Received");
  assert.equal(rcv.direction, "in");
  assert.equal(rcv.amount, "+650");
  // The deposit row keeps its full amount even though the note was later spent:
  // activity is what happened, the balance is what remains.
  assert.equal(dep.verb, "Deposited");
  assert.equal(dep.amount, "+1,000");

  for (const r of rows) {
    assert.equal(r.time, null, "the public feed has no timestamps: no time element, ever");
    assert.equal(r.counterparty, null, "selfscan rows have no single other party");
  }
  assert.equal(wd.explorerHref, "https://scan.test/tx/0xwd", "trailing slash folds away");
});

test("the presenter maps in wire order and never re-sorts", () => {
  const shuffled: HistoryItem[] = [
    { kind: "received", counterparty: null, amount: "1", txHash: "0xa", seq: 1 },
    { kind: "received", counterparty: null, amount: "1", txHash: "0xc", seq: 9 },
    { kind: "received", counterparty: null, amount: "1", txHash: "0xb", seq: 4 },
  ];
  assert.deepEqual(
    presentActivity(shuffled, "https://scan.test").map((r) => r.key),
    ["1-0xa", "9-0xc", "4-0xb"],
  );
});

test("presenter edges: counterparty display forms, a stamped row's time, unknown kinds", () => {
  // An arbiter-shaped row (counterparty + timestamp) renders base58 forms and a
  // relative time — the presenter serves both discovery modes' rows.
  const hex = `0x${"22".repeat(32)}`;
  const stamped = presentActivityRow(
    {
      kind: "sent",
      counterparty: hex,
      amount: (3n * KKRW).toString(),
      txHash: "0xs",
      seq: 11,
      blockTimestamp: Math.floor(Date.now() / 1000),
    },
    "https://scan.test",
  );
  assert.equal(stamped.amount, "-3");
  assert.equal(stamped.counterparty?.full, encodeAddress(hex), "users see base58, never hex");
  assert.equal(stamped.time, "just now");

  // A kind this bundle predates degrades: neutral direction, unsigned amount,
  // the raw kind as the verb — never a crash, never a fabricated gain/loss.
  const unknown = presentActivityRow(
    { kind: "mystery" as HistoryKind, counterparty: null, amount: KKRW.toString(), txHash: "0xu", seq: 12 },
    "https://scan.test",
  );
  assert.equal(unknown.direction, "none");
  assert.equal(unknown.amount, "1");
  assert.equal(unknown.verb, "mystery");
});

// ========================= (3) GUARD SEQUENCES ===============================

function recordedSinks(): { calls: string[]; sinks: Parameters<typeof accountGuard>[0] } {
  const calls: string[] = [];
  return {
    calls,
    sinks: {
      lock: () => calls.push("lock"),
      detachScan: () => calls.push("detach"),
      signOut: (notice) => calls.push(`signOut:${notice}`),
    },
  };
}

test("account switch: lock then detach — never a sign-out, never a store clear", () => {
  const { calls, sinks } = recordedSinks();
  const handlers = accountGuard(sinks, () => "injected");
  handlers.accountsChanged?.();
  assert.deepEqual(calls, ["lock", "detach"]);
});

test("disconnected signs out ONLY a WalletConnect session, with the pinned notice", () => {
  const wc = recordedSinks();
  accountGuard(wc.sinks, () => "walletconnect").disconnected?.();
  assert.deepEqual(wc.calls, [`signOut:${WALLET_ENDED_NOTICE}`]);

  // An extension's disconnect can be a provider hiccup: nothing happens.
  const injected = recordedSinks();
  accountGuard(injected.sinks, () => "injected").disconnected?.();
  assert.deepEqual(injected.calls, []);

  const gone = recordedSinks();
  accountGuard(gone.sinks, () => null).disconnected?.();
  assert.deepEqual(gone.calls, []);
});

test("explicit Disconnect forgets the device: bindings, stored scan, wallet link", () => {
  const calls: string[] = [];
  forgetDevice({
    clearKeyBindings: () => calls.push("bindings"),
    clearStoredScan: () => calls.push("scan"),
    endWalletLink: () => calls.push("link"),
  });
  assert.deepEqual(calls, ["bindings", "scan", "link"]);
});

// ========================= (4) AUTO-REFRESH GATE =============================

test("auto-refresh gate: hidden tab runs no pass, and a tick never overlaps itself", () => {
  assert.equal(autoTickAllowed("hidden", false), false);
  assert.equal(autoTickAllowed("visible", true), false);
  assert.equal(autoTickAllowed("visible", false), true);
});

// Source pins: App must WIRE the gated seams (a pure module nothing imports
// gates nothing), and the background pass must read the lock with peek() only —
// unlock would extend the idle deadline from a timer, defeating the re-lock.
// CONVENTION NOTE (wallet-web copy.test.ts rule): SOURCE scans are for ABSENCE;
// the PRESENCE matches below are a deliberate compromise for hook bodies no
// headless render reaches — they pin the wiring's shape, not its execution,
// and a behavior-preserving refactor may retarget them. Keep them few.
const APP_SRC = readFileSync(new URL("../src/ui/App.tsx", import.meta.url).pathname, "utf8");

test("App wires the gated seams: the guard, the forget plan, the tick gate", () => {
  assert.match(APP_SRC, /watchWallet\(\s*accountGuard\(/, "the switch guard is the wired handler set");
  assert.match(APP_SRC, /forgetDevice\(\{/, "Disconnect runs the forget plan");
  assert.match(APP_SRC, /autoTickAllowed\(document\.visibilityState/, "the interval asks the gate");
});

test("the scan path peeks the lock — a background pass never extends the idle deadline", () => {
  assert.match(APP_SRC, /keyCache\.peek\(/);
  assert.doesNotMatch(APP_SRC, /keyCache\.unlock/, "no shell path unlocks outside a user action");
});
