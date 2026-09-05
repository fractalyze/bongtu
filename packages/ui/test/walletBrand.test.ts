// Headless gates for identifying the connected wallet (packages/ui/src/walletBrand.ts) — the
// brand mark on Home and the wallet name in the lock/unlock copy both hang off this.
//
// The bug these lock down: nearly every injected wallet ALSO sets `isMetaMask: true`
// for dapp compatibility, so testing that flag first showed the MetaMask fox to Rabby,
// OKX and Trust users. A vendor's own flag must win, and an unrecognised provider must
// degrade to neutral words — never to a guessed brand.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  walletBrand,
  describeWallet,
  NEUTRAL_WALLET_NAME,
} from "../src/walletBrand.js";

const PNG_ICON = "data:image/png;base64,iVBORw0KGgo=";

// ======================= (1) BRAND FROM VENDOR FLAGS ========================

test("walletBrand: isMetaMask === true is metamask", () => {
  assert.equal(walletBrand({ isMetaMask: true }), "metamask");
  assert.equal(walletBrand({ isMetaMask: true, request: () => {} }), "metamask");
});

test("walletBrand: a vendor flag beats the MetaMask compatibility flag", () => {
  // Every one of these ships isMetaMask:true in the wild.
  assert.equal(walletBrand({ isMetaMask: true, isRabby: true }), "rabby");
  assert.equal(walletBrand({ isMetaMask: true, isCoinbaseWallet: true }), "coinbase");
  assert.equal(walletBrand({ isMetaMask: true, isOkxWallet: true }), "okx");
  assert.equal(walletBrand({ isMetaMask: true, isOKExWallet: true }), "okx");
  assert.equal(walletBrand({ isMetaMask: true, isTrust: true }), "trust");
  assert.equal(walletBrand({ isMetaMask: true, isTrustWallet: true }), "trust");
  assert.equal(walletBrand({ isMetaMask: true, isBitKeep: true }), "bitget");
  assert.equal(walletBrand({ isMetaMask: true, isPhantom: true }), "phantom");
  assert.equal(walletBrand({ isMetaMask: true, isBraveWallet: true }), "brave");
  assert.equal(walletBrand({ isMetaMask: true, isRainbow: true }), "rainbow");
  assert.equal(walletBrand({ isMetaMask: true, isZerion: true }), "zerion");
  assert.equal(walletBrand({ isMetaMask: true, isFrame: true }), "frame");
});

test("walletBrand: truthy non-boolean spoofs are NOT a brand", () => {
  assert.equal(walletBrand({ isMetaMask: 1 }), "unknown");
  assert.equal(walletBrand({ isMetaMask: "true" }), "unknown");
  assert.equal(walletBrand({ isMetaMask: {} }), "unknown");
  assert.equal(walletBrand({ isRabby: "yes" }), "unknown");
});

test("walletBrand: absent flag / false is unknown", () => {
  assert.equal(walletBrand({}), "unknown");
  assert.equal(walletBrand({ isMetaMask: false }), "unknown");
  assert.equal(walletBrand({ isSomeWalletWeNeverHeardOf: true }), "unknown");
});

test("walletBrand: non-object providers degrade without throwing", () => {
  assert.equal(walletBrand(null), "unknown");
  assert.equal(walletBrand(undefined), "unknown");
  assert.equal(walletBrand("metamask"), "unknown");
  assert.equal(walletBrand(42), "unknown");
});

// ======================= (2) WHAT THE COPY SAYS =============================

test("describeWallet: a known brand names itself and draws its own mark", () => {
  const d = describeWallet({ isMetaMask: true, isRabby: true });
  assert.equal(d.brand, "rabby");
  assert.equal(d.name, "Rabby");
  assert.equal(d.named, true);
  assert.equal(d.iconUrl, null); // nothing announced — the generic mark, never the fox
});

test("describeWallet: an unidentified wallet gets neutral words, not a guess", () => {
  const d = describeWallet({});
  assert.equal(d.brand, "unknown");
  assert.equal(d.name, NEUTRAL_WALLET_NAME);
  assert.equal(d.named, false);
});

test("describeWallet: an EIP-6963 announcement names wallets we never heard of", () => {
  const d = describeWallet({}, { name: "Kaia Wallet", icon: PNG_ICON });
  assert.equal(d.brand, "unknown");
  assert.equal(d.name, "Kaia Wallet");
  assert.equal(d.named, true);
  assert.equal(d.iconUrl, PNG_ICON);
});

test("describeWallet: the announced name wins over our hardcoded one", () => {
  // The wallet knows what it is called today; our table is a fallback.
  const d = describeWallet({ isMetaMask: true }, { name: "MetaMask Flask" });
  assert.equal(d.brand, "metamask");
  assert.equal(d.name, "MetaMask Flask");
});

test("describeWallet: a hostile announcement cannot deform the UI", () => {
  const d = describeWallet({}, { name: "Evil\n\nWallet".padEnd(400, "!"), icon: 42 });
  assert.equal(d.name.length <= 24, true);
  assert.doesNotMatch(d.name, /[\n\r]/);
  assert.equal(d.iconUrl, null);
});

test("describeWallet: only data: image icons are used", () => {
  // A remote icon URL would report every render back to the wallet vendor.
  assert.equal(describeWallet({}, { icon: "https://wallet.example/icon.png" }).iconUrl, null);
  assert.equal(describeWallet({}, { icon: "javascript:alert(1)" }).iconUrl, null);
  assert.equal(
    describeWallet({}, { icon: "data:image/svg+xml;base64,PHN2Zy8+" }).iconUrl,
    "data:image/svg+xml;base64,PHN2Zy8+",
  );
});

test("describeWallet: an empty or blank announced name falls back", () => {
  assert.equal(describeWallet({ isMetaMask: true }, { name: "   " }).name, "MetaMask");
  assert.equal(describeWallet({}, { name: "" }).name, NEUTRAL_WALLET_NAME);
});
