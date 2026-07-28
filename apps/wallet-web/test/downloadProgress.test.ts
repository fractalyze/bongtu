// The download card's aggregate only shows percent + ETA once EVERY in-flight
// asset carries a total — so the registry must seed totals from the pinned byte
// table at REGISTRATION, not from the stream. The regression this pins: the
// 95 MB transfer10x2 zkey's first chunk lags the wasm by seconds, and a
// null-until-first-chunk total left the card stuck on "0.1 MB" with no bar.

import { test } from "node:test";
import assert from "node:assert/strict";

import { ensureCircuitAssets, subscribeCircuitDownload } from "../src/lib/prove.js";
import { CIRCUIT_ASSET_BYTES } from "../src/config.js";

test("asset totals are pinned at registration, before any byte arrives", async () => {
  const states: Array<Record<string, { total: number | null }>> = [];
  const unsub = subscribeCircuitDownload("transfer10x2", (s) => {
    if (s) states.push(structuredClone(s.assets));
  });

  // A fetch that never yields a first chunk: totals must ALREADY be known.
  let sawBoth: (() => void) | null = null;
  const bothRegistered = new Promise<void>((res) => {
    sawBoth = res;
  });
  const stall = new Promise<Response>(() => {});
  void ensureCircuitAssets("transfer10x2", "/circuits", {
    cacheStorage: {
      open: async () => ({ match: async () => undefined, put: async () => {} }),
      keys: async () => [],
      delete: async () => true,
    },
    fetchFn: () => {
      if (states.length >= 1 && Object.keys(states[states.length - 1]).length === 2) sawBoth?.();
      return stall;
    },
  });
  // Both registrations happen synchronously per fetch call; wait until the
  // registry announced two assets.
  await Promise.race([bothRegistered, new Promise((r) => setTimeout(r, 200))]);
  unsub();

  const last = states[states.length - 1];
  const urls = Object.keys(last);
  assert.equal(urls.length, 2, `wasm+zkey registered, got: ${urls.join(", ")}`);
  for (const url of urls) {
    const want = url.endsWith(".wasm")
      ? CIRCUIT_ASSET_BYTES.transfer10x2.wasm
      : CIRCUIT_ASSET_BYTES.transfer10x2.zkey;
    assert.equal(last[url].total, want, `${url} total must be pinned before the first chunk`);
  }
});
