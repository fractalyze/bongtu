// Headless gates for the persisted login record (src/lib/session.ts) — the ONLY
// thing the wallet writes to browser storage. Covered:
//
//   (1) ROUND-TRIP — save → load returns the record; clear removes it.
//   (2) EXPIRY — an expired (or tokenless) record loads as null AND is removed,
//       so the next visit starts on the normal connect flow.
//   (3) SHAPE — malformed/garbage stored values load as null, never throw.
//   (4) KEY CUSTODY — the stored JSON is EXACTLY the four allowed fields; no key
//       material can ride along (belt for the security invariant the grep-gate
//       checks in source).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  SESSION_KEY,
  clearSession,
  loadSession,
  saveSession,
  type StorageLike,
  type StoredSession,
} from "../src/lib/session.js";

function memStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

const SESSION: StoredSession = {
  eoaAddress: "0x00000000000000000000000000000000000000a1",
  compressedPubkey: "0x" + "11".repeat(32),
  token: "v1.owner.9999999999.abcdef",
  exp: 9_999_999_999,
};

test("session round-trip: save → load → clear", () => {
  const st = memStorage();
  saveSession(SESSION, st);
  assert.deepEqual(loadSession(1_000, st), SESSION);
  clearSession(st);
  assert.equal(loadSession(1_000, st), null);
  assert.equal(st.map.size, 0);
});

test("expired or tokenless records load as null and are removed", () => {
  const st = memStorage();
  saveSession({ ...SESSION, exp: 500 }, st);
  assert.equal(loadSession(501, st), null, "expired session must not restore");
  assert.equal(st.map.has(SESSION_KEY), false, "expired session is cleaned up");

  saveSession({ ...SESSION, token: "", exp: 0 }, st);
  assert.equal(loadSession(1, st), null, "tokenless session must not restore");
  assert.equal(st.map.has(SESSION_KEY), false);
});

test("malformed stored values load as null and never throw", () => {
  const st = memStorage();
  for (const garbage of ["not json", "42", `{"eoaAddress":7}`, `{}`, "null"]) {
    st.map.set(SESSION_KEY, garbage);
    assert.equal(loadSession(1, st), null, `garbage ${JSON.stringify(garbage)} must load as null`);
  }
  assert.equal(loadSession(1, null), null, "no storage at all is a clean null");
});

test("the stored JSON carries EXACTLY {eoaAddress, compressedPubkey, token, exp}", () => {
  const st = memStorage();
  // Even if a caller passed extra fields, only the allowed shape may persist a
  // load — loadSession reconstructs the record from the four fields alone.
  saveSession({ ...SESSION, extra: "nope" } as unknown as StoredSession, st);
  const loaded = loadSession(1_000, st);
  assert.ok(loaded);
  assert.deepEqual(Object.keys(loaded).sort(), ["compressedPubkey", "eoaAddress", "exp", "token"]);
  // and nothing key-shaped is in the raw stored string.
  const raw = st.map.get(SESSION_KEY) ?? "";
  assert.ok(!/privateKey|keypair|formatted/i.test(raw), "no key material in the stored record");
});
