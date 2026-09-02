// Headless gates for the account-watch transition logic (connection.ts
// accountWatchHandler) — the pure closure watchWallet feeds wagmi's (account, prev)
// change pairs into. The wave-1 review finding this pins: an account switch that
// TRANSITS a disconnected state (extension lock → unlock as a DIFFERENT account)
// must still fire the account-change path, or account A's spending key stays
// unlocked for account B's user.

import { test } from "node:test";
import assert from "node:assert/strict";

import { accountWatchHandler, type WatchedAccount } from "../src/connection.js";

const connected = (address: string): WatchedAccount => ({ address, status: "connected" });
const disconnected: WatchedAccount = { status: "disconnected" };

function harness(): {
  fire: (account: WatchedAccount, prev: WatchedAccount) => void;
  switches: () => number;
  disconnects: () => number;
} {
  const counts = { switches: 0, disconnects: 0 };
  const fire = accountWatchHandler({
    accountsChanged: () => counts.switches++,
    disconnected: () => counts.disconnects++,
  });
  return { fire, switches: () => counts.switches, disconnects: () => counts.disconnects };
}

test("a direct account switch fires accountsChanged (the pre-existing path)", () => {
  const h = harness();
  h.fire(connected("0xAAA"), disconnected); // first connect: nothing to compare against
  assert.equal(h.switches(), 0);
  h.fire(connected("0xBBB"), connected("0xAAA"));
  assert.equal(h.switches(), 1);
});

test("a switch ACROSS a disconnected gap still fires (lock → unlock as another account)", () => {
  const h = harness();
  h.fire(connected("0xAAA"), disconnected);
  h.fire(disconnected, connected("0xAAA")); // extension locked
  h.fire(connected("0xBBB"), disconnected); // unlocked as a DIFFERENT account
  assert.equal(h.switches(), 1, "the gap must not swallow the switch — the keyCache relock depends on it");
});

test("reconnecting as the SAME account across a gap does not fire a spurious switch", () => {
  const h = harness();
  h.fire(connected("0xAAA"), disconnected);
  h.fire(disconnected, connected("0xAAA"));
  h.fire(connected("0xAAA"), disconnected); // same owner came back
  assert.equal(h.switches(), 0);
  // Address comparison is case-insensitive (wagmi may report checksummed forms).
  h.fire(connected("0xaaa"), connected("0xAAA"));
  assert.equal(h.switches(), 0);
});

test("a watcher attached mid-session seeds from prev: its first-seen disconnect still guards the gap", () => {
  const h = harness();
  // The first event this watcher ever sees is the DISCONNECT of an account it never
  // saw connect (App remounted the watcher after the connect happened).
  h.fire(disconnected, connected("0xAAA"));
  h.fire(connected("0xBBB"), disconnected);
  assert.equal(h.switches(), 1);
});

test("disconnected fires on every connected→disconnected edge, and only there", () => {
  const h = harness();
  h.fire(connected("0xAAA"), disconnected);
  assert.equal(h.disconnects(), 0);
  h.fire(disconnected, connected("0xAAA"));
  assert.equal(h.disconnects(), 1);
  h.fire({ status: "reconnecting" }, disconnected); // not a live-connection end
  assert.equal(h.disconnects(), 1);
});
