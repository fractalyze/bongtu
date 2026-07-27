// Headless gates for the wallet's LOCK — the in-memory hold on the spending key
// (src/lib/keyCache.ts). This is the module that decides how often the user sees a
// signature popup and how long a key stays usable, so every branch is pinned here:
//
//   (1) LAZY DERIVE — the first action derives (one popup); later actions in the same
//       page session reuse the SAME identity with no second derivation.
//   (2) ACCOUNT BINDING — a MetaMask account switch drops the hold and refuses the
//       action with the distinct mismatch error, WITHOUT spending a popup to prove it;
//       a first derivation under a foreign account is refused too (popup already spent
//       — the derived key is the only evidence there).
//   (3) IDLE WIPE, BOTH LAYERS — the armed timer drops the key and tells the UI at that
//       moment; and a use at/after the deadline re-derives even when the timer never
//       fired, because background tabs get their timers throttled.
//   (4) LOCK INDICATOR — what the header renders: locked before any action, unlocked
//       after one, locked again on wipe or sign-out, with a subscriber notified on
//       every one of those transitions.
//   (5) KEY CUSTODY — running the whole lifecycle touches NO browser storage.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveIdentityFromSignature } from "../src/lib/derive.js";
import { ACCOUNT_MISMATCH_MESSAGE } from "../src/lib/identity.js";
import { IDLE_WIPE_MS, KeyCache, type KeyCacheDeps } from "../src/lib/keyCache.js";
import type { Connection } from "../src/lib/metamask.js";

const SESSION_SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const OTHER_SIG = "0x" + "c3".repeat(32) + "d4".repeat(32) + "1b";
const SESSION = deriveIdentityFromSignature(SESSION_SIG);
const OTHER = deriveIdentityFromSignature(OTHER_SIG);

const ACCOUNT = "0x00000000000000000000000000000000000000a1";
const OTHER_ACCOUNT = "0x00000000000000000000000000000000000000b2";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const CONNECTION = { address: ACCOUNT, provider: {}, signer: {} } as any as Connection;

const MISMATCH = new RegExp(ACCOUNT_MISMATCH_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));

/** A cache on a fake clock and a hand-fired idle timer, plus the knobs a test turns:
 *  which signature the derivation returns, which account MetaMask reports, and how
 *  far the clock has moved. `fireIdle` runs the armed wipe; `armed` is false once a
 *  canceller has run, so an unarmed timer is visible to the tests. */
function harness(opts: { suppressTimer?: boolean } = {}) {
  const state = {
    sig: SESSION_SIG,
    account: ACCOUNT as string | null,
    now: 1_000_000,
    derives: 0,
    notifications: 0,
    armed: false,
  };
  let pending: (() => void) | null = null;
  const deps: Partial<KeyCacheDeps> = {
    derive: async () => {
      state.derives++;
      return deriveIdentityFromSignature(state.sig);
    },
    currentAccount: async () => state.account,
    now: () => state.now,
    arm: (fn) => {
      if (opts.suppressTimer) return () => {};
      pending = fn;
      state.armed = true;
      return () => {
        pending = null;
        state.armed = false;
      };
    },
  };
  const cache = new KeyCache(deps);
  cache.subscribe(() => {
    state.notifications++;
  });
  return {
    cache,
    state,
    unlock: () => cache.unlock(CONNECTION, SESSION.compressedPubkey),
    fireIdle: (): void => {
      assert.ok(pending, "no idle wipe is armed");
      const fn = pending;
      pending = null;
      state.armed = false;
      fn();
    },
  };
}

// ============================ (1) LAZY DERIVE ================================

test("the first action derives; later actions reuse the same key with no second popup", async () => {
  const h = harness();
  const first = await h.unlock();
  const second = await h.unlock();
  const third = await h.unlock();
  assert.equal(h.state.derives, 1, "one signature for the whole page session");
  assert.equal(first.compressedPubkey, SESSION.compressedPubkey);
  assert.equal(second, first, "the SAME identity object is handed back, not a re-derivation");
  assert.equal(third, first);
});

test("a use pushes the idle deadline out (the timer is re-armed on every unlock)", async () => {
  const h = harness();
  await h.unlock();
  h.state.now += IDLE_WIPE_MS - 1_000; // 9m59s later: still inside the window
  await h.unlock();
  assert.equal(h.state.derives, 1);
  h.state.now += IDLE_WIPE_MS - 1_000; // another 9m59s — but only ~10m since the LAST use
  await h.unlock();
  assert.equal(h.state.derives, 1, "the deadline follows the last use, not the first unlock");
});

// ============================ (2) ACCOUNT BINDING ============================

test("switching MetaMask accounts refuses the action and drops the key — with no popup", async () => {
  const h = harness();
  await h.unlock();
  assert.equal(h.state.derives, 1);

  h.state.account = OTHER_ACCOUNT;
  await assert.rejects(h.unlock(), MISMATCH);
  assert.equal(h.state.derives, 1, "the held key already proves the mismatch — no signature is spent");
  assert.equal(h.cache.isUnlocked(), false, "a refused switch leaves the wallet locked");
  assert.equal(h.state.armed, false, "the idle timer is disarmed along with the key");

  // Switching back is a normal cold start: one derivation, then usable again.
  h.state.account = ACCOUNT;
  await h.unlock();
  assert.equal(h.state.derives, 2);
  assert.equal(h.cache.isUnlocked(), true);
});

test("a FIRST derivation under a foreign account is refused and nothing is held", async () => {
  const h = harness();
  h.state.sig = OTHER_SIG; // MetaMask signs with a different account's key
  await assert.rejects(h.unlock(), MISMATCH);
  assert.equal(h.state.derives, 1, "with no held key the derivation IS the evidence");
  assert.equal(h.cache.isUnlocked(), false, "a key that isn't the session's is never held");
  assert.notEqual(OTHER.compressedPubkey, SESSION.compressedPubkey, "the fixtures must be distinct keys");
});

test("an unreadable account re-derives rather than trusting the held key", async () => {
  const h = harness();
  await h.unlock();
  h.state.account = null; // eth_accounts failed / nothing authorised
  await h.unlock();
  assert.equal(h.state.derives, 2, "no account to check against means the hold is not trustworthy");
});

// ============================ (3) IDLE WIPE, BOTH LAYERS =====================

test("layer 1 — the armed timer drops the key and flips the indicator when it fires", async () => {
  const h = harness();
  await h.unlock();
  assert.equal(h.cache.isUnlocked(), true);
  const before = h.state.notifications;

  h.fireIdle();
  assert.equal(h.cache.isUnlocked(), false, "the wipe happens at the timer, not lazily at next use");
  assert.equal(h.state.notifications, before + 1, "the header is told the moment it locks");

  h.state.now += IDLE_WIPE_MS;
  await h.unlock();
  assert.equal(h.state.derives, 2, "the next action pays one signature, like a fresh page");
});

test("layer 2 — a throttled tab whose timer never fires still re-derives past the deadline", async () => {
  const h = harness({ suppressTimer: true });
  await h.unlock();

  h.state.now += IDLE_WIPE_MS - 1; // one tick short of the deadline: still usable
  await h.unlock();
  assert.equal(h.state.derives, 1);

  h.state.now += IDLE_WIPE_MS; // a full idle span past THAT use, which reset the clock
  assert.equal(h.cache.isUnlocked(), false, "an expired key reads as locked even while held");
  await h.unlock();
  assert.equal(h.state.derives, 2, "the use-time check refuses the stale key on its own");
});

// ============================ (4) LOCK INDICATOR =============================

test("the indicator tracks every transition: fresh → unlocked → wiped → signed out", async () => {
  const h = harness();
  assert.equal(h.cache.isUnlocked(), false, "a fresh page load is locked");
  assert.equal(h.state.notifications, 0);

  await h.unlock();
  assert.equal(h.cache.isUnlocked(), true, "one action unlocks it");
  assert.equal(h.state.notifications, 1);

  h.fireIdle();
  assert.equal(h.cache.isUnlocked(), false, "ten idle minutes lock it again");
  assert.equal(h.state.notifications, 2);

  await h.unlock();
  assert.equal(h.cache.isUnlocked(), true);
  h.cache.lock(); // sign out
  assert.equal(h.cache.isUnlocked(), false, "signing out drops the key");
  assert.equal(h.state.notifications, 4);

  h.cache.lock(); // already locked
  assert.equal(h.state.notifications, 4, "no repaint when nothing changed");
});

test("unsubscribing stops the notifications", async () => {
  const h = harness();
  let seen = 0;
  const off = h.cache.subscribe(() => {
    seen++;
  });
  await h.unlock();
  assert.equal(seen, 1);
  off();
  h.cache.lock();
  assert.equal(seen, 1);
});

// ============================ (5) KEY CUSTODY ================================

test("a full unlock/reuse/wipe cycle touches no browser storage", async () => {
  const touched: string[] = [];
  const trap = (name: string): unknown =>
    new Proxy(
      {},
      {
        get: (_t, prop) => {
          touched.push(`${name}.${String(prop)}`);
          return () => undefined;
        },
        set: (_t, prop) => {
          touched.push(`${name}.${String(prop)}=`);
          return true;
        },
      },
    );
  const g = globalThis as Record<string, unknown>;
  const saved = { l: g.localStorage, s: g.sessionStorage, i: g.indexedDB, d: g.document };
  g.localStorage = trap("localStorage");
  g.sessionStorage = trap("sessionStorage");
  g.indexedDB = trap("indexedDB");
  g.document = trap("document");
  try {
    const h = harness();
    await h.unlock();
    await h.unlock();
    h.fireIdle();
    h.state.now += IDLE_WIPE_MS;
    await h.unlock();
    h.cache.lock();
  } finally {
    g.localStorage = saved.l;
    g.sessionStorage = saved.s;
    g.indexedDB = saved.i;
    g.document = saved.d;
  }
  assert.deepEqual(touched, [], "the spending key lives in memory only");
});

test("IDLE_WIPE_MS is ten minutes", () => {
  assert.equal(IDLE_WIPE_MS, 10 * 60 * 1000);
});
