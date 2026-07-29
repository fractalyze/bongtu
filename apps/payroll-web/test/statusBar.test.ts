// Gate for the status bar's state selection (lib/statusBar.ts). The one rule
// worth a headless pin: an unread balance must survive as null (the loading
// treatment) — coercing it to 0n would show a funded employer a false zero.

import { test } from "node:test";
import assert from "node:assert/strict";

import { statusBarState } from "../src/lib/statusBar.js";

const WALLET = { ethAccount: "0x1a2b000000000000000000000000000000003c4d", bongtuAddress: "0xbeef" };

test("no wallet -> the disconnected bar, whatever the balance slot says", () => {
  assert.deepEqual(statusBarState(null, null), { kind: "disconnected" });
  assert.deepEqual(statusBarState(null, 5n), { kind: "disconnected" });
});

test("connected with an unread balance keeps balance null — loading, never a false zero", () => {
  const bar = statusBarState(WALLET, null);
  assert.equal(bar.kind, "connected");
  assert.equal(bar.kind === "connected" && bar.balanceWei, null);
});

test("connected with a read balance carries account, address, and the exact wei", () => {
  const bar = statusBarState(WALLET, 123n);
  assert.deepEqual(bar, {
    kind: "connected",
    ethAccount: WALLET.ethAccount,
    bongtuAddress: WALLET.bongtuAddress,
    balanceWei: 123n,
  });
});
