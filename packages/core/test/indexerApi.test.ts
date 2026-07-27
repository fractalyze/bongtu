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
import {
  notesAuthMessage,
  viewTokenAuthMessage,
  parseSignature,
  signNotesAuth,
  verifyNotesAuth,
  packSignature,
} from "../src/eddsa.js";
import {
  buildNotesUrl,
  buildHistoryUrl,
  buildNotesTokenUrl,
  buildHistoryTokenUrl,
  signedReadUrl,
  tokenReadUrl,
  assertValidChallenge,
  viewTokenHostBinding,
} from "../src/indexerApi.js";

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

test("the /notes and /history builders are the SAME builder, differing only in path", () => {
  // All four public names are one-line wrappers over signedReadUrl / tokenReadUrl,
  // so what used to need a signature comparison is now structural.
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const base = "http://localhost:8600";

  // The token builders take no clock, so they compare exactly.
  const tokenUrl = buildNotesTokenUrl(base, compressed, "v1.tok.en");
  assert.equal(tokenUrl, tokenReadUrl(base, "notes", compressed, "v1.tok.en"));
  assert.equal(tokenUrl.replace("/notes?", "/history?"), buildHistoryTokenUrl(base, compressed, "v1.tok.en"));

  // The signed builders stamp "now", so two calls can straddle a second boundary:
  // compare the SHAPE (same params, same owner, only the route segment differs)
  // and leave the sig itself to the per-route verification tests above.
  const notesUrl = new URL(buildNotesUrl(base, compressed, kp.formattedPrivateKey));
  const histUrl = new URL(buildHistoryUrl(base, compressed, kp.formattedPrivateKey));
  assert.equal(notesUrl.pathname, "/notes");
  assert.equal(histUrl.pathname, "/history");
  assert.deepEqual([...notesUrl.searchParams.keys()], [...histUrl.searchParams.keys()]);
  assert.equal(notesUrl.searchParams.get("owner"), histUrl.searchParams.get("owner"));
  assert.equal(
    new URL(signedReadUrl(base, "history", compressed, kp.formattedPrivateKey)).pathname,
    histUrl.pathname,
  );
});

test("buildHistoryUrl rejects a malformed compressed owner pubkey (client-side 400 guard)", () => {
  assert.throws(() => buildHistoryUrl("http://localhost:8600", "0x1234", 1n));
});

// --- view-token binding primitives (the client half of POST /auth) ---------------

test("viewTokenHostBinding canonicalises to the ORIGIN, in-field", () => {
  const base = viewTokenHostBinding("https://Wallet.Example:443/indexer/");
  // scheme+host+port only: path, trailing slash, case and the default port all drop
  // out, so one deployment cannot disagree with itself over cosmetic URL spellings.
  assert.equal(base, viewTokenHostBinding("https://wallet.example"));
  assert.equal(base, viewTokenHostBinding("https://wallet.example/notes?owner=x"));
  // …while anything an attacker could control does change it.
  assert.notEqual(base, viewTokenHostBinding("http://wallet.example"));
  assert.notEqual(base, viewTokenHostBinding("https://wallet.example:8443"));
  assert.notEqual(base, viewTokenHostBinding("https://evil.example"));
  // the digest is a decimal field element the Poseidon tuple can consume.
  assert.match(base, /^[1-9][0-9]*$/);
  assert.ok(BigInt(base) < 1n << 248n);
});

test("assertValidChallenge refuses anything the issuer would not have drawn", () => {
  assert.equal(assertValidChallenge("12345"), 12345n);
  const max = (1n << 248n) - 1n;
  assert.equal(assertValidChallenge(max.toString()), max);
  for (const bad of ["", "0", "007", "-1", "1.5", "0xff", "12ab", " 12", "1" + "0".repeat(80), null, 12345]) {
    assert.throws(() => assertValidChallenge(bad), /challenge/, `accepted ${JSON.stringify(bad)}`);
  }
  assert.throws(() => assertValidChallenge((1n << 248n).toString()), /out-of-range/);
});

test("viewTokenAuthMessage is separated from notesAuthMessage by tag AND arity", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const binding = viewTokenHostBinding("https://wallet.example");
  const challenge = 987654321n;
  const viewMsg = viewTokenAuthMessage(kp.publicKey, challenge, binding);
  // Same (pub, challenge) under the legacy construction must hash elsewhere, or a
  // scraped /notes signature would redeem for a 24h token.
  assert.notEqual(viewMsg, notesAuthMessage(kp.publicKey, challenge));
  // …and the binding is load-bearing: a different origin is a different message.
  assert.notEqual(viewMsg, viewTokenAuthMessage(kp.publicKey, challenge, viewTokenHostBinding("https://evil.example")));
  // A signature over one never verifies against the other.
  const sig = signNotesAuth(kp.formattedPrivateKey, viewMsg);
  assert.ok(verifyNotesAuth(kp.publicKey, viewMsg, sig));
  assert.ok(!verifyNotesAuth(kp.publicKey, notesAuthMessage(kp.publicKey, challenge), sig));
});
