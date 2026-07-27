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

import { ActivityList } from "../src/ui/components/ActivityList.js";
import { ExplorerLink } from "../src/ui/components/ExplorerLink.js";
import { LockChip } from "../src/ui/components/LockChip.js";
import { MintModal, MintSuccess } from "../src/ui/components/MintModal.js";
import { SyncDot, syncState } from "../src/ui/components/SyncDot.js";
import { StagedProgress, SPEND_STEPS, withUnlock } from "../src/ui/components/StagedProgress.js";
import { SuccessPanel } from "../src/ui/components/SuccessPanel.js";
import { NEUTRAL_WALLET_NAME } from "../src/lib/walletBrand.js";

const h = createElement;
const TX_HASH = `0x${"ab".repeat(32)}`;
const TX_URL = `https://sepolia-explorer.giwa.io/tx/${TX_HASH}`;

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

test("the mint dialog says what minting does, and starts with an EMPTY amount", () => {
  const html = renderToStaticMarkup(
    h(MintModal, { connection: null, onClose: () => {}, onMinted: () => {} }),
  );
  assert.match(html, /Mints test kKRW to your connected account — you only pay gas\./);
  assert.match(html, /Amount \(kKRW\)/);
  assert.match(html, />Mint</);
  assert.match(html, /value=""/, "the amount field is the user's to fill in");
  assert.doesNotMatch(html, /1,000,000/, "no prefilled faucet ration");
  assert.doesNotMatch(html, /free test kKRW/);
  assert.doesNotMatch(html, /Minted — view on explorer/);
});

test("the mint dialog's completed state names the tx, links it, and offers only Close", () => {
  const html = renderToStaticMarkup(
    h(MintSuccess, { txHash: TX_HASH, explorerUrl: TX_URL, onClose: () => {} }),
  );
  assert.match(html, /Test kKRW added to your account/);
  // the hash itself, middle-shortened and mono — the receipt, not just a link
  assert.match(html, /0xababab…abab/);
  assert.match(html, /font-mono/);
  assert.match(html, />Close</);
  assert.doesNotMatch(html, />Mint</);
  assert.doesNotMatch(html, /Minting/);
  // the tx is still reachable from the completed state
  assert.match(html, /View on explorer/);
  assert.match(html, new RegExp(TX_URL.replace(/[/.]/g, "\\$&")));
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

// ======================= (5) THE NAV IS ICONS ONLY ==========================

test("the padlock renders NO text label — the words live in the tooltip and the label", () => {
  const html = renderToStaticMarkup(h(LockChip, { walletName: "Rabby" }));
  assert.doesNotMatch(html, />Locked</, "the visible Locked/Unlocked word is retired");
  assert.doesNotMatch(html, />Unlocked</);
  assert.doesNotMatch(html, /hidden sm:inline/, "and it is not merely hidden on small screens");
  // still announced, and still a live-region status
  assert.match(html, /role="status"/);
  assert.match(html, /aria-label="Wallet locked"/);
  assert.match(html, /title="Locked/);
});

test("the sync dot carries its status in a tooltip and stays a refresh button", () => {
  const synced = renderToStaticMarkup(h(SyncDot, { state: "synced", onRefresh: () => {} }));
  assert.match(synced, /title="Synced"/);
  assert.match(synced, /aria-label="Refresh balance — synced"/);
  assert.match(synced, /bg-pos/);
  assert.doesNotMatch(synced, />Synced</, "no chip text — the header is icons only");
  assert.doesNotMatch(synced, /disabled=""/, "a synced dot is pressable: it forces a refresh");

  const syncing = renderToStaticMarkup(h(SyncDot, { state: "syncing", onRefresh: () => {} }));
  assert.match(syncing, /title="Syncing…"/);
  assert.match(syncing, /bg-warn/);
  assert.match(syncing, /disabled=""/, "no re-entry while a load is already running");

  const stale = renderToStaticMarkup(h(SyncDot, { state: "stale", onRefresh: () => {} }));
  assert.match(stale, /title="Out of sync — tap to refresh"/);
  assert.match(stale, /bg-err/);
});

test("the sync state folds the page's read state together with the indexer's health", () => {
  const ok = { ok: true } as never;
  const behind = { ok: false } as never;
  const base = { health: ok, healthErrored: false, refreshing: false, dataError: false };
  assert.equal(syncState(base), "synced");
  assert.equal(syncState({ ...base, refreshing: true }), "syncing", "a load in flight wins");
  assert.equal(syncState({ ...base, dataError: true }), "stale", "a failed read is not green");
  assert.equal(syncState({ ...base, healthErrored: true }), "stale", "an unreachable indexer either");
  assert.equal(syncState({ ...base, health: behind }), "stale", "nor one that reports itself behind");
  assert.equal(
    syncState({ ...base, health: null }),
    "syncing",
    "an unanswered first health check is not yet a promise",
  );
});

test("Home's nav is the four icons, in order, with no words and no refresh button", () => {
  const home = readFileSync(`${UI_DIR}screens/Home.tsx`, "utf8");
  const nav = home.slice(home.indexOf("<header"), home.indexOf("</header>"));
  const order = ["IndexerSyncDot", "LockChip", "WalletMark", "IconGear"];
  let at = -1;
  for (const mark of order) {
    const i = nav.indexOf(mark);
    assert.ok(i > at, `${mark} is missing from the nav or out of order`);
    at = i;
  }
  assert.doesNotMatch(nav, /IconRefresh/, "the standalone refresh button is retired");
  assert.doesNotMatch(nav, /wallet\.named/, "the wallet's NAME never renders in the nav");
});

// ======================= (6) ACTIVITY ROWS ==================================

const HISTORY_ROW = {
  seq: 7,
  kind: "sent" as const,
  amount: "100000000000000000000",
  counterparty: `0x${"11".repeat(32)}`,
  txHash: `0x${"cd".repeat(32)}`,
  blockTimestamp: Math.floor(Date.now() / 1000),
};

test("an activity amount names the token, and the sign keeps its direction", () => {
  const html = renderToStaticMarkup(
    h(ActivityList, {
      history: [HISTORY_ROW, { ...HISTORY_ROW, seq: 8, kind: "received" as const }],
      loading: false,
      explorerBase: "https://sepolia-explorer.giwa.io",
    }),
  );
  assert.match(html, /-100<span[^>]*>kKRW<\/span>/, "outgoing reads -100 kKRW");
  assert.match(html, /\+100<span[^>]*>kKRW<\/span>/, "incoming reads +100 kKRW");
  // the symbol is the muted sidekick of the number, as on the balance hero
  assert.match(html, /<span class="text-muted font-semibold text-\[0\.72rem\] ml-1">kKRW<\/span>/);
});

test("the row list is ruled at BOTH edges, so its gaps read evenly", () => {
  const html = renderToStaticMarkup(
    h(ActivityList, {
      history: [HISTORY_ROW],
      loading: false,
      explorerBase: "https://sepolia-explorer.giwa.io",
    }),
  );
  // a closing rule under the last row ...
  assert.match(html, /flex flex-col border-b border-border/);
  // ... and the first row keeps its own top rule (no first:border-t-0 escape)
  const source = readFileSync(`${UI_DIR}components/ActivityList.tsx`, "utf8");
  assert.doesNotMatch(source, /first:border-t-0/);
  assert.match(html, /border-t border-border/);
});

// ======================= (7) SETTINGS IS FACTS + LOGOUT =====================

test("Settings keeps the three facts and Disconnect — the rest is retired", () => {
  const settings = readFileSync(`${UI_DIR}screens/Settings.tsx`, "utf8");
  assert.match(settings, /label="Network"/);
  assert.match(settings, /label="Pool"/);
  assert.match(settings, /label="Token \(kKRW\)"/, "the token row names the token");
  assert.match(settings, /Disconnect\s*<\/Button>/);
  assert.match(settings, /Disconnecting signs you out/);

  for (const gone of [
    "Arbiter indexer URL",
    "Save Indexer URL",
    "setIndexerUrl",
    'label="Token"',
    'label="Batch size"',
    'label="Key version"',
    'label="Arbiter key"',
    'label="Your address"',
  ]) {
    assert.ok(!settings.includes(gone), `Settings still carries "${gone}"`);
  }
});

test("nothing in the app can still set an indexer URL at runtime", () => {
  for (const { file, text } of uiSources()) {
    assert.doesNotMatch(text, /setIndexerUrl/, `${file} still wires the retired override`);
  }
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
