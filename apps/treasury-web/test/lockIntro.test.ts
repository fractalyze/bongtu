// Headless gates for the once-per-device lock explainer:
//
//   (1) GATING — it belongs to a FRESH login on a device that has not seen it. Seen
//       once, never again; a restored session never shows it at all (it explains the
//       unlock a login performs, and a restore performs none).
//   (2) WHAT IT STORES — one boolean under one key. This is the only localStorage
//       write besides the session record, and it is not key material.
//   (3) WHAT IT SAYS — the three lines that make the header padlock make sense.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  LOCK_INTRO_KEY,
  hasSeenLockIntro,
  markLockIntroSeen,
  shouldShowLockIntro,
} from "@bongtu/ui/lockIntro";
import type { StorageLike } from "@bongtu/client/session";
import { LockIntro } from "../src/ui/screens/LockIntro.js";

/** An in-memory localStorage stand-in (the app passes the real one). */
function fakeStorage(initial: Record<string, string> = {}): StorageLike & { map: Map<string, string> } {
  const map = new Map(Object.entries(initial));
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => {
      map.set(k, v);
    },
    removeItem: (k) => {
      map.delete(k);
    },
  };
}

// ============================ (1) GATING =====================================

test("a fresh login on an unmarked device shows the explainer", () => {
  assert.equal(shouldShowLockIntro("connect", fakeStorage()), true);
});

test("a device that has seen it never sees it again", () => {
  const storage = fakeStorage();
  assert.equal(shouldShowLockIntro("connect", storage), true);
  markLockIntroSeen(storage);
  assert.equal(shouldShowLockIntro("connect", storage), false);
});

test("a restored session never shows it, marked or not", () => {
  assert.equal(shouldShowLockIntro("restore", fakeStorage()), false);
  const seen = fakeStorage({ [LOCK_INTRO_KEY]: "1" });
  assert.equal(shouldShowLockIntro("restore", seen), false);
});

test("unreadable storage shows it rather than swallowing it", () => {
  const blocked: StorageLike = {
    getItem: () => {
      throw new Error("storage blocked");
    },
    setItem: () => {
      throw new Error("storage blocked");
    },
    removeItem: () => {},
  };
  assert.equal(hasSeenLockIntro(blocked), false);
  assert.equal(shouldShowLockIntro("connect", blocked), true);
  assert.doesNotThrow(() => markLockIntroSeen(blocked), "a blocked write must not break the login");
  assert.equal(shouldShowLockIntro("connect", null), true, "no storage at all behaves the same");
});

// ============================ (2) WHAT IT STORES =============================

test("the flag is one boolean under one key — no key material, no identifiers", () => {
  const storage = fakeStorage();
  markLockIntroSeen(storage);
  assert.deepEqual([...storage.map.entries()], [[LOCK_INTRO_KEY, "1"]]);
  assert.equal(LOCK_INTRO_KEY, "bongtu.lockIntro.v1");
});

test("a foreign value in the flag's slot does not count as seen", () => {
  assert.equal(hasSeenLockIntro(fakeStorage({ [LOCK_INTRO_KEY]: "yes" })), false);
});

// ============================ (3) WHAT IT SAYS ===============================

test("the explainer states the three facts and offers one way on", () => {
  const html = renderToStaticMarkup(createElement(LockIntro, { onDone: () => {} }));
  assert.match(html, /only exists while this page is open. It is never saved anywhere/);
  assert.match(html, /If you do nothing for 10 minutes, the wallet locks itself/);
  assert.match(html, /The padlock at the top closes/);
  assert.match(html, /confirm once in your wallet app/);
  assert.match(html, /Your balance is always visible, locked or not/);
  assert.match(html, />Got it</);
});
