// Gates for the Receive panel's one-time deposit address surface (Slice ⑤
// U-P4 wallet half). Two kinds of check, per the copy.test.ts split:
//
//   LOGIC — the payName.ts seam (name lookup, claim persistence, issuance
//     outcome mapping) drives with a fake client + fake storage, so the
//     ownership check and the unconfigured-404 copy gate headlessly.
//   RENDERED — PortalAddressSection is a pure function of its props, so
//     react-dom/server reads the real markup: disabled-without-name, the
//     issued-address + payer explanation, the distinct 404 copy.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { NameRecord, PortalIssuance } from "@bongtu/core/indexerApi";
import type { StorageLike } from "@bongtu/client/session";
import {
  PAY_NAME_KEY,
  PORTAL_UNCONFIGURED_MESSAGE,
  detectPayName,
  issueOneTimeAddress,
  recallPayName,
  rememberPayName,
  verifyOwnName,
} from "../src/lib/payName.js";
import { PortalAddressSection, type PortalIssueView } from "../src/ui/components/ReceivePanel.js";

const h = createElement;

const OWNER = "0x" + "ab".repeat(32);
const OTHER = "0x" + "cd".repeat(32);
const INDEXER = "http://indexer.test";
// EIP-55 mixed case straight off the wire — the surface must show it verbatim.
const DESTINATION = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";

function record(owner: string): NameRecord {
  return { name: "alice", owner, viewPub: "0x" + "11".repeat(32), spendPub: "0x02" + "22".repeat(32), updatedAt: 1 };
}

// In-memory StorageLike — the session.ts injection seam.
function memStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

// ============================ (1) NAME LOOKUP ===============================

test("verifyOwnName accepts only a name whose directory record belongs to the session owner", async () => {
  const resolve = async (): Promise<NameRecord | null> => record(OWNER);
  assert.equal(await verifyOwnName(INDEXER, "Alice", OWNER, resolve), "alice"); // normalized
  assert.equal(await verifyOwnName(INDEXER, "alice", OTHER, resolve), null); // foreign owner
  assert.equal(await verifyOwnName(INDEXER, "alice", OWNER, async () => null), null); // unregistered
  // grammar-invalid names never reach the network
  const calls = { n: 0 };
  const counting = async (): Promise<NameRecord | null> => {
    calls.n++;
    return record(OWNER);
  };
  assert.equal(await verifyOwnName(INDEXER, "x", OWNER, counting), null);
  assert.equal(calls.n, 0, "an invalid name must not hit the resolver");
});

test("verifyOwnName propagates a network failure instead of reading it as 'no name'", async () => {
  await assert.rejects(
    verifyOwnName(INDEXER, "alice", OWNER, async () => {
      throw new Error("indexer unreachable");
    }),
    /indexer unreachable/,
  );
});

test("recall/remember: the claim is per-owner — another session's record is not an answer", () => {
  const storage = memStorage();
  rememberPayName(OWNER, "alice", storage);
  assert.equal(recallPayName(OWNER, storage), "alice");
  assert.equal(recallPayName(OTHER, storage), null);
  assert.ok(storage.map.has(PAY_NAME_KEY));
});

test("detectPayName re-checks the remembered claim and un-links a stale mapping", async () => {
  const storage = memStorage();
  rememberPayName(OWNER, "alice", storage);
  assert.equal(
    await detectPayName(INDEXER, OWNER, { storage, resolve: async () => record(OWNER) }),
    "alice",
  );
  // the directory now maps the name to someone else -> disabled, not misissued
  assert.equal(
    await detectPayName(INDEXER, OWNER, { storage, resolve: async () => record(OTHER) }),
    null,
  );
  // nothing remembered -> null without touching the network
  assert.equal(
    await detectPayName(INDEXER, OTHER, {
      storage,
      resolve: async () => {
        throw new Error("must not resolve without a claim");
      },
    }),
    null,
  );
});

// ============================ (2) ISSUANCE ==================================

test("issueOneTimeAddress returns the wire destination verbatim (EIP-55 kept)", async () => {
  const pay = async (): Promise<PortalIssuance> => ({
    destination: DESTINATION,
    ephemeralPub: "0x" + "33".repeat(32),
    viewTag: 7,
    stealthAddr: "0x" + "44".repeat(20),
    factory: "0x" + "55".repeat(20),
  });
  const out = await issueOneTimeAddress(INDEXER, "alice", pay);
  assert.deepEqual(out, { ok: true, destination: DESTINATION });
});

test("the unconfigured-factory 404 maps to its own copy; other failures pass through", async () => {
  // the exact thrown shape postJson produces for the server's unconfigured body
  const unconfigured = async (): Promise<PortalIssuance> => {
    throw new Error(
      `${INDEXER}/pay/alice -> 404: {"error":"portal deposits are not configured on this indexer (PORTAL_FACTORY unset)"}`,
    );
  };
  const out = await issueOneTimeAddress(INDEXER, "alice", unconfigured);
  assert.equal(out.ok, false);
  assert.ok(!out.ok && out.unconfigured, "PORTAL_FACTORY-unset 404 is the distinct case");
  assert.equal(!out.ok && out.message, PORTAL_UNCONFIGURED_MESSAGE);

  const nameGone = async (): Promise<PortalIssuance> => {
    throw new Error(`${INDEXER}/pay/alice -> 404: {"error":"name not registered","name":"alice"}`);
  };
  const gone = await issueOneTimeAddress(INDEXER, "alice", nameGone);
  assert.ok(!gone.ok && !gone.unconfigured, "an unknown-name 404 is NOT the unconfigured case");
  assert.ok(!gone.ok && gone.message.includes("name not registered"), "the server's text surfaces as-is");
});

// ============================ (3) RENDERED SURFACE ==========================

const IDLE: PortalIssueView = { issuing: false, destination: null, error: null };

function renderSection(name: string | null, issue: PortalIssueView = IDLE): string {
  return renderToStaticMarkup(
    h(PortalAddressSection, {
      name,
      claimValue: "",
      claimBusy: false,
      claimError: null,
      onClaimChange: () => {},
      onClaimSubmit: () => {},
      issue,
      onIssue: () => {},
    }),
  );
}

test("without a linked name the issue button is disabled and the copy says why", () => {
  const html = renderSection(null);
  assert.match(html, /One-time deposit address/);
  assert.match(html, /registered payment name/);
  const issueButton = html.match(/<button[^>]*>Get one-time address<\/button>/);
  assert.ok(issueButton, "the issue button renders in the no-name state");
  // the ATTRIBUTE, not Tailwind's disabled: variant classes
  assert.match(issueButton![0], /\sdisabled=""/, "no name -> the issue button is disabled");
});

test("with a linked name the issue button is live and carries the name", () => {
  const html = renderSection("alice");
  const issueButton = html.match(/<button[^>]*>Get one-time address for alice<\/button>/);
  assert.ok(issueButton, "the issue button names the linked payment name");
  assert.ok(!/\sdisabled=""/.test(issueButton![0]), "a linked name enables issuance");
});

test("an issued destination renders verbatim with the payer-facing explanation and a copy button", () => {
  const html = renderSection("alice", { issuing: false, destination: DESTINATION, error: null });
  assert.ok(html.includes(DESTINATION), "the checksummed destination shows verbatim");
  assert.match(html, /any wallet or exchange/, "explains the plain-transfer payer path");
  assert.match(html, /shielded balance automatically/, "explains where the deposit lands");
  assert.match(html, /issued\s*fresh/i, "explains single-use-fresh per payer");
  assert.match(html, /Copy Deposit Address/);
});

test("an issuance failure renders its message (the unconfigured copy included)", () => {
  const html = renderSection("alice", { issuing: false, destination: null, error: PORTAL_UNCONFIGURED_MESSAGE });
  // matched on an apostrophe-free fragment: react-dom escapes ' to &#x27;
  assert.match(html, /set up on this indexer yet/);
});
