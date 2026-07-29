// Headless gates for what the wallet writes to browser storage (src/session.ts) —
// the login record, and the account→key binding. Covered:
//
//   (1) ROUND-TRIP — save → load returns the record; clear removes it.
//   (2) EXPIRY — an expired (or tokenless) record loads as null AND is removed,
//       so the next visit starts on the normal connect flow.
//   (3) SHAPE — malformed/garbage stored values load as null, never throw.
//   (4) KEY CUSTODY — the stored JSON is EXACTLY the allowed fields; no key
//       material can ride along (belt for the security invariant the grep-gate
//       checks in source).
//   (5) TRANSPORT — which way the login came in, so the silent restore reopens the
//       same one; records written before WalletConnect existed still restore.
//   (6) BINDINGS — per account, outliving the session, forgotten on sign-out.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  KEY_BINDING_KEY,
  SESSION_KEY,
  clearKeyBindings,
  clearSession,
  loadKeyBinding,
  loadSession,
  saveKeyBinding,
  saveSession,
  type StorageLike,
  type StoredSession,
} from "../src/session.js";

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
  // A record written before WalletConnect existed carries no transport; it loads as
  // the transport it was made on, so the silent restore keeps working across the
  // upgrade instead of dropping every returning user back to Onboarding.
  assert.deepEqual(loadSession(1_000, st), { ...SESSION, transport: "injected" });
  clearSession(st);
  assert.equal(loadSession(1_000, st), null);
  assert.equal(st.map.size, 0);
});

test("a WalletConnect session says so, and an unknown transport is not trusted", () => {
  const st = memStorage();
  saveSession({ ...SESSION, transport: "walletconnect" }, st);
  assert.equal(loadSession(1_000, st)?.transport, "walletconnect");

  st.map.set(SESSION_KEY, JSON.stringify({ ...SESSION, transport: "carrier-pigeon" }));
  assert.equal(
    loadSession(1_000, st)?.transport,
    "injected",
    "a transport this build has no code for must not be handed to the restore",
  );
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

test("the stored JSON carries EXACTLY {eoaAddress, compressedPubkey, token, exp, transport}", () => {
  const st = memStorage();
  // Even if a caller passed extra fields, only the allowed shape may persist a
  // load — loadSession reconstructs the record from the known fields alone.
  saveSession({ ...SESSION, extra: "nope" } as unknown as StoredSession, st);
  const loaded = loadSession(1_000, st);
  assert.ok(loaded);
  assert.deepEqual(Object.keys(loaded).sort(), [
    "compressedPubkey",
    "eoaAddress",
    "exp",
    "token",
    "transport",
  ]);
  // and nothing key-shaped is in the raw stored string.
  const raw = st.map.get(SESSION_KEY) ?? "";
  assert.ok(!/privateKey|keypair|formatted/i.test(raw), "no key material in the stored record");
});

// --- the account→key binding -------------------------------------------------------
// A second record, and the only thing that can catch a wallet whose signatures drift
// (loginGuard.ts). What matters about it: it outlives the session, it holds nothing
// secret, and an explicit Disconnect forgets it.

test("a binding round-trips per account, and is unknown for an account never seen", () => {
  const st = memStorage();
  assert.equal(loadKeyBinding(SESSION.eoaAddress, st), null, "nothing remembered yet");

  saveKeyBinding(SESSION.eoaAddress, SESSION.compressedPubkey, st);
  assert.equal(loadKeyBinding(SESSION.eoaAddress, st), SESSION.compressedPubkey);
  // The wallet reports addresses in whatever case it likes; the binding is per account.
  assert.equal(loadKeyBinding(SESSION.eoaAddress.toUpperCase(), st), SESSION.compressedPubkey);
  assert.equal(loadKeyBinding("0x" + "cc".repeat(20), st), null);
});

test("two accounts on one device keep their own keys", () => {
  const st = memStorage();
  const second = "0x" + "dd".repeat(20);
  saveKeyBinding(SESSION.eoaAddress, SESSION.compressedPubkey, st);
  saveKeyBinding(second, "0x" + "22".repeat(32), st);
  assert.equal(loadKeyBinding(SESSION.eoaAddress, st), SESSION.compressedPubkey);
  assert.equal(loadKeyBinding(second, st), "0x" + "22".repeat(32));
});

test("bindings survive a session expiring, and are forgotten only on an explicit sign-out", () => {
  const st = memStorage();
  saveSession(SESSION, st);
  saveKeyBinding(SESSION.eoaAddress, SESSION.compressedPubkey, st);

  clearSession(st);
  assert.equal(
    loadKeyBinding(SESSION.eoaAddress, st),
    SESSION.compressedPubkey,
    "an expired token says nothing about which key the account derives",
  );

  clearKeyBindings(st);
  assert.equal(loadKeyBinding(SESSION.eoaAddress, st), null);
  assert.equal(st.map.size, 0);
});

test("a corrupt or hostile binding record reads as 'nothing remembered', never throws", () => {
  const st = memStorage();
  for (const garbage of ["not json", "42", "null", "[1,2]", `{"0xa1":{"nested":true}}`]) {
    st.map.set(KEY_BINDING_KEY, garbage);
    assert.equal(loadKeyBinding(SESSION.eoaAddress, st), null, `garbage ${garbage}`);
  }
  assert.equal(loadKeyBinding(SESSION.eoaAddress, null), null, "no storage at all is a clean null");
});

test("the binding record holds nothing secret", () => {
  const st = memStorage();
  saveKeyBinding(SESSION.eoaAddress, SESSION.compressedPubkey, st);
  const raw = st.map.get(KEY_BINDING_KEY) ?? "";
  assert.ok(!/privateKey|keypair|formatted/i.test(raw), "public key and address only");
});
