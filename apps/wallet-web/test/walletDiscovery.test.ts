// Headless gates for EIP-6963 wallet discovery (src/lib/eip6963.ts) and for the rule
// that decides WHICH provider gets identified (injectedFrom, walletBrand.ts).
//
// The load-bearing claim: a silently-restored session identifies its wallet without
// anything being persisted about it. reconnect() rebuilds an ethers Web3Provider over
// the SAME injected object the wallet announced itself with, so the announcement still
// matches by object identity and the name/icon come back unchanged.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  announcedWallet,
  startWalletDiscovery,
  subscribeWallets,
  walletDiscoveryVersion,
} from "../src/lib/eip6963.js";
import { describeWallet, injectedFrom, NEUTRAL_WALLET_NAME } from "../src/lib/walletBrand.js";

const ICON = "data:image/png;base64,iVBORw0KGgo=";

// Two injected wallets, both flying the MetaMask compatibility flag.
const rabby = { isMetaMask: true, isRabby: true };
const okx = { isMetaMask: true, isOkxWallet: true };

// The page has no window in this env; discovery needs one to listen on, and an
// EventTarget is exactly the surface it uses (addEventListener + dispatchEvent).
function fakeWindow(): EventTarget {
  const win = new EventTarget();
  (globalThis as { window?: unknown }).window = win;
  return win;
}

function announce(win: EventTarget, provider: unknown, name: string, icon?: string): void {
  win.dispatchEvent(
    new CustomEvent("eip6963:announceProvider", { detail: { info: { name, icon }, provider } }),
  );
}

const win = fakeWindow();
let requested = 0;
win.addEventListener("eip6963:requestProvider", () => {
  requested += 1;
});
startWalletDiscovery();
startWalletDiscovery(); // idempotent: a second call must not double-listen

test("discovery asks the installed wallets to announce, exactly once", () => {
  assert.equal(requested, 1);
});

test("an announcement is remembered against the provider object that sent it", () => {
  announce(win, rabby, "Rabby", ICON);
  announce(win, okx, "OKX Wallet");

  assert.deepEqual(announcedWallet(rabby), { name: "Rabby", icon: ICON });
  assert.deepEqual(announcedWallet(okx), { name: "OKX Wallet", icon: undefined });
  // a provider nobody announced, and the no-wallet case
  assert.equal(announcedWallet({ isMetaMask: true }), null);
  assert.equal(announcedWallet(null), null);
});

test("a malformed announcement is ignored rather than stored", () => {
  const before = walletDiscoveryVersion();
  win.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: { info: { name: "x" } } }));
  assert.equal(walletDiscoveryVersion(), before);
});

test("subscribers hear late announcements (the name can arrive after first paint)", () => {
  let hits = 0;
  const stop = subscribeWallets(() => {
    hits += 1;
  });
  const late = { isMetaMask: true };
  const before = walletDiscoveryVersion();
  announce(win, late, "Late Wallet");
  assert.equal(hits, 1);
  assert.equal(walletDiscoveryVersion(), before + 1);
  assert.equal(describeWallet(late, announcedWallet(late)).name, "Late Wallet");

  stop();
  announce(win, { isMetaMask: true }, "Another");
  assert.equal(hits, 1, "an unsubscribed listener stops hearing");
});

test("a restored session identifies its wallet with nothing persisted", () => {
  // What reconnect() hands back: an ethers Web3Provider wrapping the SAME injected
  // object, plus the address from eth_accounts.
  const restored = { address: "0xabc", provider: { provider: rabby }, signer: {} };

  const fresh = describeWallet(rabby, announcedWallet(rabby));
  const after = (() => {
    const injected = injectedFrom(restored, null);
    return describeWallet(injected, announcedWallet(injected));
  })();

  assert.deepEqual(after, fresh);
  assert.equal(after.brand, "rabby");
  assert.equal(after.name, "Rabby");
  assert.equal(after.iconUrl, ICON);
});

test("injectedFrom: no connection yet falls back to the page's wallet", () => {
  assert.equal(injectedFrom(null, okx), okx);
  assert.equal(injectedFrom({ address: "0x1", provider: {}, signer: {} }, okx), okx);
  // nothing installed at all — describe it in neutral words, never a guess
  assert.equal(injectedFrom(null, undefined), null);
  assert.equal(describeWallet(injectedFrom(null, undefined)).name, NEUTRAL_WALLET_NAME);
});
