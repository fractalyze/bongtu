// Headless gate for the /notes signed-query protocol's CLIENT half (SPEC §6b v2).
// `buildNotesUrl` (src/indexerApi.ts) is the one client-side implementation; the
// indexer route verifies with the sdk's own `verifyNotesAuth`. This suite replays
// the route's exact checks (unpack owner, parse sig, rebuild the Poseidon-bound
// message from the ts param, verify) against a URL the client just built — so a
// drift in param names, ts units, sig packing, or message binding fails HERE, in
// milliseconds, instead of only in the anvil conformance gate.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "../src/note.js";
import { packPubkey, unpackPubkey } from "../src/pubkey.js";
import { notesAuthMessage, parseSignature, signNotesAuth, verifyNotesAuth, packSignature } from "../src/eddsa.js";
import { buildNotesUrl, buildHistoryUrl } from "../src/indexerApi.js";

const OWNER_SCALAR = 424242424242424242424242n;

function parts(url: string): { u: URL; owner: string; ts: number; sig: string } {
  const u = new URL(url);
  const owner = u.searchParams.get("owner");
  const ts = u.searchParams.get("ts");
  const sig = u.searchParams.get("sig");
  assert.ok(owner && ts && sig, `URL missing owner/ts/sig params: ${url}`);
  return { u, owner: owner as string, ts: Number(ts), sig: sig as string };
}

test("buildNotesUrl output passes the indexer route's exact verification steps", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const url = buildNotesUrl("http://localhost:8600/", compressed, kp.formattedPrivateKey);

  const { u, owner, ts, sig } = parts(url);
  assert.equal(u.pathname, "/notes"); // trailing base slash trimmed, no "//notes"
  assert.equal(owner, compressed); // owner round-trips through the query encoding

  // ts is unix SECONDS and inside the server's 300s replay window "now".
  assert.ok(Number.isInteger(ts), `ts not an integer: ${ts}`);
  assert.ok(Math.abs(Math.floor(Date.now() / 1000) - ts) <= 5, "ts not fresh unix seconds");

  // The route's checks, in order: unpack owner, parse sig, rebuild the message
  // from (ownerPub, ts), verify against the queried key.
  const pub = unpackPubkey(owner);
  const parsed = parseSignature(sig);
  assert.ok(verifyNotesAuth(pub, notesAuthMessage(pub, ts), parsed), "client-built sig rejected by the server-side verifier");
});

test("the built sig binds to the owner key and the ts (no cross-owner / replay reuse)", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const other = deriveKeypair(777777777n);
  const url = buildNotesUrl("http://localhost:8600", packPubkey(kp.publicKey), kp.formattedPrivateKey);
  const { ts, sig } = parts(url);
  const parsed = parseSignature(sig);

  const pub = unpackPubkey(packPubkey(kp.publicKey));
  // wrong owner: a stranger's pubkey must reject the same query
  assert.equal(verifyNotesAuth(other.publicKey, notesAuthMessage(other.publicKey, ts), parsed), false);
  // tampered ts: shifting the window must reject
  assert.equal(verifyNotesAuth(pub, notesAuthMessage(pub, ts + 1), parsed), false);
});

test("buildNotesUrl signs identically for bigint and decimal-string private keys", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const url = buildNotesUrl("http://localhost:8600", compressed, kp.formattedPrivateKey.toString());
  const { ts, sig } = parts(url);
  // Deterministic signing (Poseidon nonce): the sig param must equal a direct
  // sign over the SAME (pub, ts) — pinning the exact construction the route expects.
  const pub = unpackPubkey(compressed);
  const expected = packSignature(signNotesAuth(kp.formattedPrivateKey, notesAuthMessage(pub, ts)));
  assert.equal(sig, expected);
});

test("buildNotesUrl rejects a malformed compressed owner pubkey (client-side 400 guard)", () => {
  assert.throws(() => buildNotesUrl("http://localhost:8600", "0x1234", 1n));
});

// --- /history mirrors /notes EXACTLY (same auth, only the path differs) ----------

test("buildHistoryUrl output passes the indexer route's exact verification steps", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const url = buildHistoryUrl("http://localhost:8600/", compressed, kp.formattedPrivateKey);

  const { u, owner, ts, sig } = parts(url);
  assert.equal(u.pathname, "/history"); // only the path differs from /notes
  assert.equal(owner, compressed); // owner round-trips through the query encoding

  // ts is unix SECONDS and inside the server's 300s replay window "now".
  assert.ok(Number.isInteger(ts), `ts not an integer: ${ts}`);
  assert.ok(Math.abs(Math.floor(Date.now() / 1000) - ts) <= 5, "ts not fresh unix seconds");

  // The /history route's checks are identical to /notes: unpack owner, parse sig,
  // rebuild the message from (ownerPub, ts), verify against the queried key.
  const pub = unpackPubkey(owner);
  const parsed = parseSignature(sig);
  assert.ok(verifyNotesAuth(pub, notesAuthMessage(pub, ts), parsed), "client-built sig rejected by the server-side verifier");
});

test("buildHistoryUrl signs the SAME (pub, ts) message as buildNotesUrl (only the path differs)", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const url = buildHistoryUrl("http://localhost:8600", compressed, kp.formattedPrivateKey);
  const { ts, sig } = parts(url);
  // Deterministic signing (Poseidon nonce): the sig must equal a direct sign over
  // Poseidon(ownerPub.x, ownerPub.y, ts) — the exact construction the route expects.
  const pub = unpackPubkey(compressed);
  const expected = packSignature(signNotesAuth(kp.formattedPrivateKey, notesAuthMessage(pub, ts)));
  assert.equal(sig, expected);
});

test("buildHistoryUrl rejects a malformed compressed owner pubkey (client-side 400 guard)", () => {
  assert.throws(() => buildHistoryUrl("http://localhost:8600", "0x1234", 1n));
});
