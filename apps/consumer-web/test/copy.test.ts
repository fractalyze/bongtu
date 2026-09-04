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

import { ActionStubs, ACTIONS_STUB_NOTICE } from "../src/ui/screens/Home.js";

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

// ======================= (1) THE STUBBED ACTIONS =============================

test("the action grid renders Send/Withdraw/Deposit DISABLED, with the honest notice", () => {
  const html = renderToStaticMarkup(h(ActionStubs));
  for (const label of ["Send", "Withdraw", "Deposit"]) {
    assert.match(html, new RegExp(`>${label}<`), `${label} renders`);
  }
  // Three buttons, all disabled: nothing in this slice can start an op.
  assert.equal((html.match(/<button/g) ?? []).length, 3);
  assert.equal((html.match(/disabled=""/g) ?? []).length, 3);
  assert.ok(html.includes(ACTIONS_STUB_NOTICE), "the notice renders under the grid");
});

test("the stub notice promises only what works: receive, not send", () => {
  assert.match(ACTIONS_STUB_NOTICE, /arrive in the next update/);
  assert.match(ACTIONS_STUB_NOTICE, /already receive/);
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
