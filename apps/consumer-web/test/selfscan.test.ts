// Headless gates for the discovery shell's scan-driven states (the wallet-web
// selfscan suite, ported onto this app's always-selfscan shape):
//
//   (1) SYNC STATE — the pure dot fold (SyncDot.tsx selfScanSyncState): freshness
//       is the scan cursor vs the public /head, a load in flight wins, any failure
//       reads stale, and nothing is green before both sides have answered.
//   (2) SCAN STORE — the localStorage wiring degrades to "rescan from the start"
//       wherever storage is unavailable (this node process included): no throw,
//       loads null.
//   (3) NOTICES — the pure scanNotice fold: pending kem delivery wins, a locked
//       wallet earns the locked strip, an unlocked fully-delivered scan earns
//       nothing.
//   (4) BALANCE STATES — the hero never fabricates a zero: a null balance renders
//       the loading ellipsis or the dash, never "0"; a LOADED zero renders "0"
//       (the truth). And a scan-derived activity row (no blockTimestamp — the
//       public feed has none) renders NO time element, never the epoch date.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { BalanceCard } from "../src/ui/components/BalanceCard.js";
import { ActivityList } from "../src/ui/components/ActivityList.js";
import type { HistoryItem } from "@bongtu/core/indexerApi";
import { selfScanSyncState } from "../src/ui/components/SyncDot.js";
import { clearScanState, loadScanState, saveScanState, scanNotice } from "../src/lib/scanStore.js";
import {
  EMPTY_SCAN_STATE,
  SELF_SCAN_LOCKED_NOTICE,
  SELF_SCAN_PENDING_NOTICE,
  type PendingDiscovery,
  type SelfScanState,
} from "@bongtu/client/selfscan";

// ============================ (1) SYNC STATE =================================

const HEAD = { root: "1", nextLeafIndex: 10 };

test("selfScanSyncState: a load in flight wins, then any failure, then the cursor comparison", () => {
  const base = { head: HEAD, headErrored: false, scannedNextLeafIndex: 10, refreshing: false, dataError: false };
  assert.equal(selfScanSyncState({ ...base, refreshing: true }), "syncing");
  assert.equal(selfScanSyncState({ ...base, dataError: true }), "stale");
  assert.equal(selfScanSyncState({ ...base, headErrored: true, head: null }), "stale");
  // scan covered everything /head reports: green.
  assert.equal(selfScanSyncState(base), "synced");
  // the tree grew past the scan: tap to rescan.
  assert.equal(selfScanSyncState({ ...base, scannedNextLeafIndex: 8 }), "stale");
  // a scan stamped ahead of a lagging /head read is still covered: green.
  assert.equal(selfScanSyncState({ ...base, scannedNextLeafIndex: 12 }), "synced");
});

test("selfScanSyncState: nothing is green before both sides have answered", () => {
  const base = { head: HEAD, headErrored: false, scannedNextLeafIndex: 10, refreshing: false, dataError: false };
  assert.equal(selfScanSyncState({ ...base, head: null }), "syncing");
  assert.equal(selfScanSyncState({ ...base, scannedNextLeafIndex: null }), "syncing");
});

// ============================ (2) SCAN STORE =================================

test("scanStore degrades without localStorage: no throw, null load (a full rescan)", () => {
  // This node process has no window.localStorage — exactly the blocked-storage
  // browser case the wiring must survive.
  assert.equal(loadScanState("0xabc"), null);
  assert.doesNotThrow(() => saveScanState("0xabc", EMPTY_SCAN_STATE));
  assert.doesNotThrow(() => clearScanState("0xabc"));
});

// ============================ (3) NOTICES ====================================

const PENDING: PendingDiscovery = { seq: 3, txHash: "0xab", batchId: null, status: "pending" } as PendingDiscovery;
const withPending: SelfScanState = { ...EMPTY_SCAN_STATE, pending: [PENDING] };

test("scanNotice: pending kem delivery wins, then the locked strip, then nothing", () => {
  assert.equal(scanNotice(withPending, true), SELF_SCAN_PENDING_NOTICE);
  // pending is the more actionable fact even while locked: no unlock could
  // reveal a note whose kem chunks have not landed.
  assert.equal(scanNotice(withPending, false), SELF_SCAN_PENDING_NOTICE);
  assert.equal(scanNotice(EMPTY_SCAN_STATE, false), SELF_SCAN_LOCKED_NOTICE);
  assert.equal(scanNotice(EMPTY_SCAN_STATE, true), null);
});

// ============================ (4) BALANCE STATES =============================

// A pubkey short enough that shortenPubkey passes it through unshortened — the
// hero's loading ellipsis must be the ONLY "…" in the markup, or the assertions
// below would pass on the address chip instead of the balance.
const CARD = (balance: bigint | null, loading: boolean): string =>
  renderToStaticMarkup(
    h(BalanceCard, { balance, loading, pubkey: "3abcShort", onOpenReceive: () => {} }),
  );

test("the balance hero never fabricates a zero: null renders loading/dash, never 0", () => {
  const loadingCard = CARD(null, true);
  assert.ok(loadingCard.includes("…"), "loading renders the ellipsis");
  assert.ok(!loadingCard.includes(">0<"), "no fabricated zero while loading");
  const idleCard = CARD(null, false);
  assert.ok(idleCard.includes("—"), "an unloaded balance renders the dash");
  assert.ok(!idleCard.includes(">0<"), "no fabricated zero before a scan lands");
});

test("a LOADED zero balance renders 0 — the scan's truth, not a placeholder", () => {
  const html = CARD(0n, false);
  assert.ok(html.includes(">0<"), "the loaded zero renders as the number");
  assert.ok(!html.includes("…") && !html.includes("—"), "no placeholder competes with it");
});

test("a scan-derived activity row (no blockTimestamp) renders no time element — never an epoch date", () => {
  // deriveScanActivity emits rows WITHOUT blockTimestamp; the display edge
  // must suppress the time element, not render relativeTime(0)'s 1970 date.
  const row: HistoryItem = { kind: "received", counterparty: null, amount: "600", txHash: "0xabc", seq: 3 };
  const html = renderToStaticMarkup(
    h(ActivityList, { history: [row], loading: false, explorerBase: "https://scan.test" }),
  );
  assert.ok(html.includes("Received"), "the verb still renders");
  assert.ok(!html.includes("1969") && !html.includes("1970"), "no epoch date leaks into the row");
  assert.ok(!html.includes("ago") && !html.includes("just now"), "no fabricated relative time");
});
