// Headless gates for the wallet's selfscan (no-auditor) profile wiring:
//
//   (1) DISCOVERY MODE — the ENV-derived config flag (config.ts
//       discoveryFromEnv, the testnetFromEnv pattern): only the literal
//       "selfscan" flips the no-auditor profile on; everything else — unset,
//       empty, garbage — stays the enterprise arbiter path, so every existing
//       deployment keeps its byte-identical behavior. Under the node runner
//       (no Vite env) DEFAULTS.discovery must therefore be "arbiter".
//   (2) SELFSCAN SYNC STATE — the pure dot fold (SyncDot.tsx
//       selfScanSyncState): freshness is the scan cursor vs the public /head,
//       a load in flight wins, any failure reads stale, and nothing is green
//       before both sides have answered.
//   (3) SCAN STORE — the localStorage wiring degrades to "rescan from the
//       start" wherever storage is unavailable (this node process included):
//       no throw, loads null.
//   (4) SELFSCAN ACTIVITY ROW — a derived row carries no blockTimestamp (the
//       public feed has none), and the ActivityList display edge renders NO
//       time element for it — never relativeTime(0)'s epoch date.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { DEFAULTS, discoveryFromEnv, isSelfScan } from "../src/config.js";
import { ActivityList } from "../src/ui/components/ActivityList.js";
import type { HistoryItem } from "@bongtu/client/indexerClient";
import { selfScanSyncState } from "../src/ui/components/SyncDot.js";
import { loadScanState, saveScanState, clearScanState } from "../src/lib/scanStore.js";
import { EMPTY_SCAN_STATE } from "@bongtu/client/selfscan";

// ============================ (1) DISCOVERY MODE =============================

test("discoveryFromEnv: only the literal 'selfscan' leaves the arbiter default", () => {
  assert.equal(discoveryFromEnv(undefined), "arbiter");
  assert.equal(discoveryFromEnv(""), "arbiter");
  assert.equal(discoveryFromEnv("arbiter"), "arbiter");
  assert.equal(discoveryFromEnv("true"), "arbiter");
  assert.equal(discoveryFromEnv("SELFSCAN"), "arbiter", "case-sensitive: no accidental flips");
  assert.equal(discoveryFromEnv("selfscan"), "selfscan");
  // The ONE mode gate the shell and screens share (no inline re-derivations).
  assert.equal(isSelfScan("selfscan"), true);
  assert.equal(isSelfScan("arbiter"), false);
});

test("the node-runner build (no Vite env) is the enterprise arbiter profile", () => {
  assert.equal(DEFAULTS.discovery, "arbiter");
});

// ============================ (2) SYNC STATE =================================

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

// ============================ (3) SCAN STORE =================================

test("scanStore degrades without localStorage: no throw, null load (a full rescan)", () => {
  // This node process has no window.localStorage — exactly the blocked-storage
  // browser case the wiring must survive.
  assert.equal(loadScanState("0xabc"), null);
  assert.doesNotThrow(() => saveScanState("0xabc", EMPTY_SCAN_STATE));
  assert.doesNotThrow(() => clearScanState("0xabc"));
});

// ====================== (4) SELFSCAN ACTIVITY ROW ============================

test("a selfscan activity row (no blockTimestamp) renders no time element — never an epoch date", () => {
  // deriveScanActivity emits rows WITHOUT blockTimestamp; the display edge
  // must suppress the time element, not render relativeTime(0)'s 1970 date.
  const row: HistoryItem = { kind: "received", counterparty: null, amount: "600", txHash: "0xabc", seq: 3 };
  const html = renderToStaticMarkup(
    h(ActivityList, { history: [row], loading: false, explorerBase: "https://scan.test" }),
  );
  assert.ok(html.includes("Received"), "the verb still renders");
  assert.ok(!html.includes("1969") && !html.includes("1970"), "no epoch date leaks into the row");
  assert.ok(!html.includes("ago") && !html.includes("just now"), "no fabricated relative time");

  // An arbiter row (timestamp present) keeps its relative time untouched.
  const stamped: HistoryItem = { ...row, blockTimestamp: Math.floor(Date.now() / 1000) };
  const stampedHtml = renderToStaticMarkup(
    h(ActivityList, { history: [stamped], loading: false, explorerBase: "https://scan.test" }),
  );
  assert.ok(stampedHtml.includes("just now"));
});
