// Headless gate for the download card copy helper (src/ui/format.ts). The subtitle
// carries the REAL asset size (from the live download total, whose denominator is
// config.CIRCUIT_ASSET_BYTES) — never a hardcoded number — and stays size-free
// while the total is unknown.

import { test } from "node:test";
import assert from "node:assert/strict";

import { downloadOnceSubtitle } from "../src/ui/format.js";
import { CIRCUIT_ASSET_BYTES } from "../src/config.js";

test("downloadOnceSubtitle sizes from the actual byte total", () => {
  const t = CIRCUIT_ASSET_BYTES.transfer;
  const total = t.wasm + t.zkey;
  const expectedMb = Math.round(total / (1024 * 1024));
  assert.equal(downloadOnceSubtitle(total), `Runs on your device — downloads once (${expectedMb} MB)`);
  // plain-words copy: no jargon anywhere in the line
  assert.ok(!/zkey|circuit|snark|proof/i.test(downloadOnceSubtitle(total)));
});

test("downloadOnceSubtitle omits the size while the total is unknown", () => {
  assert.equal(downloadOnceSubtitle(null), "Runs on your device — downloads once");
  assert.equal(downloadOnceSubtitle(0), "Runs on your device — downloads once");
});
