// Headless gate for the download card copy helper (src/ui/format.ts). The subtitle
// carries the REAL asset size (from the live download total, whose denominator is
// config.CIRCUIT_ASSET_BYTES) — never a hardcoded number — and stays size-free
// while the total is unknown.

import { test } from "node:test";
import assert from "node:assert/strict";

import { amountError, downloadOnceSubtitle } from "../src/ui/format.js";
import { CIRCUIT_ASSET_BYTES } from "../src/config.js";

const ONE_KKRW = 10n ** 18n;

test("amountError passes an amount the balance covers", () => {
  assert.equal(amountError("5", 10n * ONE_KKRW), null);
  assert.equal(amountError("10", 10n * ONE_KKRW), null, "spending it all is allowed");
});

test("amountError rejects a malformed, zero or over-balance amount", () => {
  assert.equal(amountError("", 10n * ONE_KKRW), "Enter an amount.");
  assert.equal(amountError("0", 10n * ONE_KKRW), "Amount must be greater than zero.");
  assert.equal(amountError("11", 10n * ONE_KKRW), "Amount exceeds your balance.");
});

test("amountError names WHICH balance the amount overran", () => {
  // Send/Withdraw judge the private balance; Deposit judges the account's public kKRW.
  assert.equal(
    amountError("11", 10n * ONE_KKRW, "Amount exceeds your kKRW balance."),
    "Amount exceeds your kKRW balance.",
  );
});

test("amountError cannot judge a balance that has not loaded", () => {
  // The screens keep their own Continue guard for this — a proof started here would
  // revert on-chain.
  assert.equal(amountError("999999", null), null);
  assert.equal(amountError("0", null), "Amount must be greater than zero.", "but the parse rules still apply");
});

test("downloadOnceSubtitle sizes from the actual byte total", () => {
  const t = CIRCUIT_ASSET_BYTES.transfer;
  const total = t.wasm + t.zkey;
  const expectedMb = Math.round(total / (1024 * 1024));
  assert.equal(downloadOnceSubtitle(total), `Runs on your device. Downloads only once (${expectedMb} MB)`);
  // plain-words copy: no jargon anywhere in the line
  assert.ok(!/zkey|circuit|snark|proof/i.test(downloadOnceSubtitle(total)));
});

test("downloadOnceSubtitle omits the size while the total is unknown", () => {
  assert.equal(downloadOnceSubtitle(null), "Runs on your device. Downloads only once");
  assert.equal(downloadOnceSubtitle(0), "Runs on your device. Downloads only once");
});
