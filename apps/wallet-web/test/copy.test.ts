// Gates for what the screens SAY and SHOW. Two kinds of check, for two kinds of fact:
//
//   RENDERED — components whose output is a pure function of their props go through
//     react-dom/server, so the assertions read the real markup (button sets, the
//     explorer link's icon, an interpolated wallet name).
//   SOURCE — a retired line is an ABSENCE, and the phases it used to live in (confirm,
//     success) sit behind component state that no headless render can reach. Scanning
//     the screen sources is the honest gate for "this copy is gone and stays gone".

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ExplorerLink } from "../src/ui/components/ExplorerLink.js";
import { LockChip } from "../src/ui/components/LockChip.js";
import { MintModal, MintSuccess } from "../src/ui/components/MintModal.js";
import { StagedProgress, SPEND_STEPS, withUnlock } from "../src/ui/components/StagedProgress.js";
import { SuccessPanel } from "../src/ui/components/SuccessPanel.js";
import { NEUTRAL_WALLET_NAME } from "../src/lib/walletBrand.js";

const h = createElement;
const TX_URL = "https://sepolia-explorer.giwa.io/tx/0xabc";

// The rendered SVG carries no readable name, so the icon is identified by its path
// data — the one thing that differs between Remix glyphs.
const EXTERNAL_LINK_ICON = /<svg[^>]*>[\s\S]*?<\/svg>/;

const UI_DIR = new URL("../src/ui/", import.meta.url).pathname;

function uiSources(): { file: string; text: string }[] {
  const out: { file: string; text: string }[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}${entry.name}`;
      if (entry.isDirectory()) walk(`${path}/`);
      else if (entry.name.endsWith(".tsx")) out.push({ file: path, text: readFileSync(path, "utf8") });
    }
  };
  walk(UI_DIR);
  return out;
}

// ======================= (1) SUCCESS SCREENS ================================

test("SuccessPanel shows the headline, the amount and an explorer link with its icon", () => {
  const html = renderToStaticMarkup(
    h(SuccessPanel, {
      title: "Deposit",
      headline: "Deposit completed",
      amount: "1,000",
      explorerUrl: TX_URL,
      syncing: false,
    }),
  );
  assert.match(html, /Deposit completed/);
  assert.match(html, /1,000/);
  assert.match(html, new RegExp(TX_URL.replace(/[/.]/g, "\\$&")));
  assert.match(html, /View on explorer/);
  assert.match(html, EXTERNAL_LINK_ICON);
  // The Done button is the only way on; nothing promises anything about the balance
  // while the indexer has not caught up yet.
  assert.match(html, />Done</);
  assert.doesNotMatch(html, /Now in your private balance/);
});

test("SuccessPanel says the balance is catching up only while syncing", () => {
  const syncing = renderToStaticMarkup(
    h(SuccessPanel, {
      title: "Send",
      headline: "Payment sent",
      amount: "5",
      explorerUrl: TX_URL,
      syncing: true,
    }),
  );
  assert.match(syncing, /Updating your balance/);
});

test("the success headlines are the corrected ones", () => {
  const deposit = readFileSync(`${UI_DIR}screens/Deposit.tsx`, "utf8");
  const spend = readFileSync(`${UI_DIR}components/SpendScreen.tsx`, "utf8");
  assert.match(deposit, /headline="Deposit completed"/);
  assert.doesNotMatch(deposit, /Deposit complete[^d]/);
  // "sent" headlines were already correct and stay untouched.
  assert.match(spend, /"Payment sent"/);
  assert.match(spend, /"Withdrawal sent"/);
});

test("ExplorerLink is the ONE explorer link — no screen hand-rolls a bare one", () => {
  const html = renderToStaticMarkup(h(ExplorerLink, { href: TX_URL }));
  assert.match(html, /target="_blank"/);
  assert.match(html, /rel="noreferrer"/);
  assert.match(html, /View on explorer/);
  assert.match(html, EXTERNAL_LINK_ICON);
  for (const { file, text } of uiSources()) {
    if (file.endsWith("ExplorerLink.tsx")) continue;
    assert.doesNotMatch(text, /on explorer\s*</, `${file} renders an explorer link of its own`);
  }
});

// ======================= (2) MINT DIALOG ====================================

test("the mint dialog is the amount field and Mint — no suggested-amount pitch", () => {
  const html = renderToStaticMarkup(
    h(MintModal, { connection: null, onClose: () => {}, onMinted: () => {} }),
  );
  assert.match(html, /Amount \(kKRW\)/);
  assert.match(html, />Mint</);
  assert.doesNotMatch(html, /free test kKRW/);
  assert.doesNotMatch(html, /Minted — view on explorer/);
});

test("the mint dialog's completed state offers Close and NOT Mint", () => {
  const html = renderToStaticMarkup(h(MintSuccess, { explorerUrl: TX_URL, onClose: () => {} }));
  assert.match(html, /Test kKRW added to your account/);
  assert.match(html, />Close</);
  assert.doesNotMatch(html, />Mint</);
  assert.doesNotMatch(html, /Minting/);
  // the tx is still reachable from the completed state
  assert.match(html, /View on explorer/);
});

// ======================= (3) RETIRED LINES ==================================

test("the on-your-device reassurance is gone from the action screens", () => {
  for (const { file, text } of uiSources()) {
    assert.doesNotMatch(text, /Everything happens on your device/, `${file} still repeats it`);
  }
});

test("Confirm Send / Confirm Withdraw no longer restate the source of the money", () => {
  const spend = readFileSync(`${UI_DIR}components/SpendScreen.tsx`, "utf8");
  assert.doesNotMatch(spend, /Your private balance/);
  // the rows that carry real information stay
  assert.match(spend, />To</);
  assert.match(spend, />Network</);
});

// ======================= (4) WALLET NAME IN COPY ============================

test("the unlock line names the connected wallet, and falls back to neutral words", () => {
  const named = renderToStaticMarkup(
    h(StagedProgress, {
      stage: "unlock",
      elapsed: 0,
      steps: withUnlock(SPEND_STEPS),
      walletName: "Rabby",
    }),
  );
  assert.match(named, /Confirm in Rabby to unlock your wallet/);
  assert.doesNotMatch(named, /MetaMask/);

  const anonymous = renderToStaticMarkup(
    h(StagedProgress, { stage: "unlock", elapsed: 0, steps: withUnlock(SPEND_STEPS) }),
  );
  assert.match(anonymous, new RegExp(`Confirm in ${NEUTRAL_WALLET_NAME} to unlock`));
});

test("the lock chip's tooltip names the connected wallet", () => {
  const named = renderToStaticMarkup(h(LockChip, { walletName: "OKX Wallet" }));
  assert.match(named, /Locked/);
  assert.match(named, /confirm once in OKX Wallet/);

  const anonymous = renderToStaticMarkup(h(LockChip, {}));
  assert.match(anonymous, new RegExp(`confirm once in ${NEUTRAL_WALLET_NAME}`));
});

test("no screen hardcodes a wallet brand in what the user reads", () => {
  for (const { file, text } of uiSources()) {
    // icons.tsx draws the fox and WalletMark.tsx decides when it is the right mark;
    // Onboarding offers the MetaMask mobile app deep link — the one case where there
    // is no installed wallet to detect.
    const brandAware = ["icons.tsx", "WalletMark.tsx", "Onboarding.tsx"];
    if (brandAware.some((f) => file.endsWith(f))) continue;
    assert.doesNotMatch(text, /MetaMask/, `${file} names a brand instead of the detected wallet`);
  }
});
