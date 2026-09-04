// Gates for what the SHELL says and ships. Two kinds of check, for two kinds of
// fact (the wallet-web copy.test.ts pattern):
//
//   RENDERED — components whose output is a pure function of their props go
//     through react-dom/server, so the assertions read the real markup (the
//     stubbed action grid).
//   SOURCE — the not-coming-along list (issue #13) is a set of ABSENCES, and an
//     absence sits behind no renderable state. Scanning the app sources is the
//     honest gate for "this coupling is gone and stays gone".

import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { HomeActions } from "../src/ui/screens/Home.js";
import { SyncDot } from "../src/ui/components/SyncDot.js";
import { ActivityList } from "../src/ui/components/ActivityList.js";
import { chainSteps, StagedProgress, WAITING_SCAN_LINE } from "../src/ui/components/StagedProgress.js";
import { OP_IN_FLIGHT_MESSAGE } from "../src/ui/actionMachine.js";
import { WITHDRAW_PROOF_BOUND_NOTE } from "../src/ui/screens/SpendScreen.js";
import { DEPOSIT_RECIPIENT_HINT } from "../src/ui/screens/Deposit.js";
import {
  RECIPIENT_NOT_REGISTERED_MESSAGE,
  RECIPIENT_V1_ONLY_MESSAGE,
} from "../src/lib/payName.js";
import {
  ACTIVITY_EMPTY_TEXT,
  ACTIVITY_LOADING_TEXT,
  activityEmptyLine,
} from "../src/ui/activityView.js";
import { WALLET_ENDED_NOTICE } from "../src/lib/accountGuard.js";
import { SELF_SCAN_LOCKED_NOTICE, SELF_SCAN_PENDING_NOTICE } from "@bongtu/client/selfscan";

const SRC_DIR = new URL("../src/", import.meta.url).pathname;

function appSources(): { file: string; text: string }[] {
  const out: { file: string; text: string }[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = `${dir}${entry.name}`;
      if (entry.isDirectory()) walk(`${path}/`);
      else if (/\.tsx?$/.test(entry.name)) out.push({ file: path, text: readFileSync(path, "utf8") });
    }
  };
  walk(SRC_DIR);
  return out;
}

test("the action grid is live: Send/Receive/Withdraw/Deposit, every op behind a real screen", () => {
  const html = renderToStaticMarkup(h(HomeActions));
  for (const label of ["Send", "Receive", "Withdraw", "Deposit"]) {
    assert.match(html, new RegExp(`>${label}<`), `${label} renders`);
  }
  assert.equal((html.match(/<button/g) ?? []).length, 4);
  assert.equal((html.match(/disabled=""/g) ?? []).length, 0, "nothing is stubbed anymore");
});

// ======================= (2) THE NOT-COMING-ALONG LIST =======================

// Each token names a coupling issue #13 keeps OUT of this bundle: the authority
// key, the view-token session machinery, signed membership reads, owner-authed
// reads, activity paging, the discovery-mode knob, and the sponsored-exit
// client. A hit anywhere in src/ is a regression toward the enterprise wallet.
const BANNED_TOKENS = [
  "arbiterPubKey",
  "obtainViewToken",
  "buildNotesTokenUrl",
  "ARBITER_PUBKEY",
  "ARBITER_KEM",
  "getSignedPath",
  "assertPoolKemEpoch",
  "asOwner(",
  "historyPage",
  "loadMoreHistory",
  "relayerClient",
  "relayerUrl",
  "VITE_DISCOVERY",
  "DiscoveryMode",
];

test("no enterprise coupling survives in the app sources", () => {
  for (const { file, text } of appSources()) {
    for (const token of BANNED_TOKENS) {
      assert.ok(!text.includes(token), `${file} still carries "${token}"`);
    }
  }
});

test("the shell is always self-scan: the consumer dot only, no health-report dot", () => {
  const home = readFileSync(`${SRC_DIR}ui/screens/Home.tsx`, "utf8");
  assert.match(home, /SelfScanSyncDot/);
  assert.doesNotMatch(home, /IndexerSyncDot/);
  const dot = readFileSync(`${SRC_DIR}ui/components/SyncDot.tsx`, "utf8");
  assert.doesNotMatch(dot, /fetchHealth/, "freshness is the scan cursor vs /head, nothing else");
});

test("activity is the whole scan-derived feed: no pager copy anywhere", () => {
  for (const { file, text } of appSources()) {
    assert.ok(!text.includes("Load more"), `${file} offers a pager the scan cannot honor`);
  }
});

test("logins are tokenless by construction: the engine's tokenless variant, tokens never persist", () => {
  const app = readFileSync(`${SRC_DIR}ui/App.tsx`, "utf8");
  assert.match(app, /runTokenlessLogin/);
  const store = readFileSync(`${SRC_DIR}lib/sessionStore.ts`, "utf8");
  assert.match(store, /token: ""/, "the loaded record states the tokenless truth");
});

// ======================= (3) WALLET-WEB RULES THAT CARRY OVER ================

test("no screen hardcodes a wallet brand in what the user reads", () => {
  for (const { file, text } of appSources()) {
    // icons.tsx draws the fox and WalletMark.tsx decides when it is the right
    // mark; Onboarding offers the mobile-app deep link — the one case where
    // there is no installed wallet to detect; wagmi.ts documents that link;
    // faucet.ts's provenance comment (a verbatim wallet-web copy) names the
    // wallet the mint was measured in, never in user-facing copy.
    const brandAware = ["icons.tsx", "WalletMark.tsx", "Onboarding.tsx", "wagmi.ts", "walletBrand.ts", "faucet.ts"];
    if (brandAware.some((f) => file.endsWith(f))) continue;
    assert.doesNotMatch(text, /MetaMask/, `${file} names a brand instead of the detected wallet`);
  }
});

// ======================= (4) DISCOVERY-SURFACE COPY PINS =====================

// Every notice the discovery screens surface, word-for-word: the calm strips
// come from the engine (selfscan.ts), the disconnect notice from the guard —
// a drift here silently changes what users are told about their money.
test("the discovery notices are pinned word-for-word", () => {
  assert.equal(
    SELF_SCAN_PENDING_NOTICE,
    "Some incoming payments are still being delivered. They'll appear once delivery completes.",
  );
  assert.equal(
    SELF_SCAN_LOCKED_NOTICE,
    "Wallet locked. Showing your last scan. Unlock to check for new payments.",
  );
  assert.equal(WALLET_ENDED_NOTICE, "Your wallet ended the connection. Connect again to continue.");
});

test("the sync dot carries its status in a tooltip and stays a refresh button", () => {
  const dot = (state: "synced" | "syncing" | "stale"): string =>
    renderToStaticMarkup(h(SyncDot, { state, onRefresh: () => {} }));
  assert.ok(dot("synced").includes('title="Synced"'));
  assert.ok(dot("syncing").includes('title="Syncing…"'));
  assert.ok(dot("stale").includes('title="Out of sync. Tap to refresh"'));
  // While a refresh is already running the button disarms; stale keeps it live —
  // the tap IS the recovery.
  assert.ok(dot("syncing").includes('disabled=""'));
  assert.ok(!dot("stale").includes('disabled=""'));
});

// ======================= (5) OP-SURFACE COPY PINS ============================

test("the op-surface copy is pinned: the self-scan wait, the proof-bound payout, the one-op refusal", () => {
  assert.equal(
    WAITING_SCAN_LINE,
    "Scanning the network for your combined note. This wallet finds its own money.",
  );
  assert.equal(
    WITHDRAW_PROOF_BOUND_NOTE,
    "The payout address is locked into your proof. Once you confirm, it cannot be redirected by anyone.",
  );
  assert.equal(
    OP_IN_FLIGHT_MESSAGE,
    "Another action is still running. Let it finish before starting a new one.",
  );
  assert.match(DEPOSIT_RECIPIENT_HINT, /payment name/);
  // the waiting line renders under the active leg of a chained run
  const html = renderToStaticMarkup(
    h(StagedProgress, { stage: "leg0", describeKey: "waiting", elapsed: 0, steps: chainSteps(2, "Sending") }),
  );
  assert.ok(html.includes(WAITING_SCAN_LINE));
});

test("the registry-rule copy is pinned word-for-word", () => {
  assert.equal(
    RECIPIENT_NOT_REGISTERED_MESSAGE,
    "That name isn't registered. Check the spelling with the recipient.",
  );
  assert.equal(
    RECIPIENT_V1_ONLY_MESSAGE,
    "This recipient can’t receive private payments yet. Ask them to register their payment name from their own consumer wallet first.",
  );
});

test("sends are registry-name-only: no address grammar reaches the op screens, one resolve seam", () => {
  const spend = readFileSync(`${SRC_DIR}ui/screens/SpendScreen.tsx`, "utf8");
  const deposit = readFileSync(`${SRC_DIR}ui/screens/Deposit.tsx`, "utf8");
  assert.doesNotMatch(spend, /decodeAddress/, "no pasteable address path exists in v1");
  assert.match(spend, /resolveConsumerRecipient/);
  assert.match(deposit, /resolveConsumerRecipient/);
});

test("the empty feed says loading while a scan runs, and 'No activity yet.' after", () => {
  assert.equal(ACTIVITY_LOADING_TEXT, "Loading activity…");
  assert.equal(ACTIVITY_EMPTY_TEXT, "No activity yet.");
  assert.equal(activityEmptyLine(true), ACTIVITY_LOADING_TEXT);
  assert.equal(activityEmptyLine(false), ACTIVITY_EMPTY_TEXT);
  const empty = (loading: boolean): string =>
    renderToStaticMarkup(h(ActivityList, { history: [], loading, explorerBase: "https://scan.test" }));
  assert.ok(empty(true).includes(ACTIVITY_LOADING_TEXT));
  assert.ok(empty(false).includes(ACTIVITY_EMPTY_TEXT));
});
