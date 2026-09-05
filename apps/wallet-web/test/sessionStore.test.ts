// Gate for the consumer login record (lib/sessionStore.ts): the module that
// decides whether a stale, corrupt, or cross-deployment login silently
// restores. The engine SessionStore cannot carry this record (it drops
// tokenless rows by contract), so the restore contract lives app-side and is
// pinned here through an injected StorageLike, never the real localStorage.

import { test } from "node:test";
import assert from "node:assert/strict";

import { DEPLOYMENT_TAG } from "@bongtu/core/network";
import type { StorageLike } from "@bongtu/client/session";
import {
  CONSUMER_SESSION_KEY,
  clearConsumerSession,
  loadConsumerSession,
  saveConsumerSession,
} from "../src/lib/sessionStore.js";

function fakeStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
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

const RECORD = {
  eoaAddress: "0x1111111111111111111111111111111111111111",
  compressedPubkey: "0x" + "22".repeat(32),
  transport: "walletconnect" as const,
};

test("round-trip: a saved record loads as the tokenless truth, not a fallback", () => {
  const s = fakeStorage();
  saveConsumerSession(RECORD, s);
  const loaded = loadConsumerSession(s);
  assert.deepEqual(loaded, { ...RECORD, token: "", exp: 0 });
});

test("the key is deployment-scoped: a record from another (chainId, pool) reads as absent", () => {
  // The KDF domain is (chainId, pool); after a chain move the stored pubkey
  // names a key this build cannot derive, so the OLD deployment's key must
  // not be readable through the NEW build's key string.
  assert.ok(CONSUMER_SESSION_KEY.endsWith(DEPLOYMENT_TAG), "key carries the deployment tag");
  const s = fakeStorage();
  s.map.set("bongtu.consumer.session.other-deployment", JSON.stringify(RECORD));
  assert.equal(loadConsumerSession(s), null);
});

test("malformed records are removed and read as null, so the next visit starts clean", () => {
  const cases = [
    "not json at all",
    JSON.stringify({ compressedPubkey: RECORD.compressedPubkey }),
    JSON.stringify({ eoaAddress: RECORD.eoaAddress }),
    JSON.stringify({ eoaAddress: 7, compressedPubkey: RECORD.compressedPubkey }),
  ];
  for (const raw of cases) {
    const s = fakeStorage();
    s.map.set(CONSUMER_SESSION_KEY, raw);
    assert.equal(loadConsumerSession(s), null, `${raw.slice(0, 30)} must read as absent`);
    assert.equal(s.map.has(CONSUMER_SESSION_KEY), false, "…and the broken record is gone");
  }
});

test("an unrecognised transport degrades to injected rather than being trusted", () => {
  const s = fakeStorage();
  s.map.set(
    CONSUMER_SESSION_KEY,
    JSON.stringify({ ...RECORD, transport: "carrier-pigeon" }),
  );
  assert.equal(loadConsumerSession(s)?.transport, "injected");
});

test("clear removes the record; a null storage never throws on any operation", () => {
  const s = fakeStorage();
  saveConsumerSession(RECORD, s);
  clearConsumerSession(s);
  assert.equal(loadConsumerSession(s), null);

  saveConsumerSession(RECORD, null);
  assert.equal(loadConsumerSession(null), null);
  clearConsumerSession(null);
});
