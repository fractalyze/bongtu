// Headless gates for the PURE provider-brand detection (src/lib/walletBrand.ts) the
// connected-wallet card keys its brand mark on: strictly isMetaMask === true is
// MetaMask; anything else — absent flag, truthy spoof values, null/undefined/primitive
// providers — degrades to "unknown" (generic wallet icon), never throws.

import { test } from "node:test";
import assert from "node:assert/strict";

import { walletBrand } from "../src/lib/walletBrand.js";

test("walletBrand: isMetaMask === true is metamask", () => {
  assert.equal(walletBrand({ isMetaMask: true }), "metamask");
  assert.equal(walletBrand({ isMetaMask: true, request: () => {} }), "metamask");
});

test("walletBrand: truthy non-boolean spoofs are NOT metamask", () => {
  assert.equal(walletBrand({ isMetaMask: 1 }), "unknown");
  assert.equal(walletBrand({ isMetaMask: "true" }), "unknown");
  assert.equal(walletBrand({ isMetaMask: {} }), "unknown");
});

test("walletBrand: absent flag / false is unknown", () => {
  assert.equal(walletBrand({}), "unknown");
  assert.equal(walletBrand({ isMetaMask: false }), "unknown");
  assert.equal(walletBrand({ isRabby: true }), "unknown");
});

test("walletBrand: non-object providers degrade without throwing", () => {
  assert.equal(walletBrand(null), "unknown");
  assert.equal(walletBrand(undefined), "unknown");
  assert.equal(walletBrand("metamask"), "unknown");
  assert.equal(walletBrand(42), "unknown");
});
