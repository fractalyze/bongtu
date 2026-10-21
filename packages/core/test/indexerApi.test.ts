// Headless gate for the /notes signed-query protocol's CLIENT half (SPEC §6b v2).
// `buildNotesUrl` (src/indexerApi.ts) is the one client-side implementation; the
// indexer route verifies with the sdk's own `verifyNotesAuth`. This suite replays
// the route's exact checks (unpack owner, parse sig, rebuild the Poseidon-bound
// message from the ts param, verify) against a URL the client just built — so a
// drift in param names, ts units, sig packing, or message binding fails HERE, in
// milliseconds, instead of only in the anvil conformance gate.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey, unpackPubkey } from "@bongtu/core/pubkey";
import {
  notesAuthMessage,
  viewTokenAuthMessage,
  parseSignature,
  signNotesAuth,
  verifyNotesAuth,
  packSignature,
} from "@bongtu/core/eddsa";
import {
  buildNotesUrl,
  buildHistoryUrl,
  buildNotesTokenUrl,
  buildHistoryTokenUrl,
  buildHistoryPageUrl,
  fetchHistoryPage,
  HISTORY_PAGE_LIMIT,
  type HistoryPage,
  signedReadUrl,
  tokenReadUrl,
  assertValidChallenge,
  viewTokenHostBinding,
  normalizeName,
  registerName,
  resolveName,
  getAnnouncements,
  type NameRecord,
  type NameRegistration,
  type WithdrawAnnouncementRecord,
} from "@bongtu/core/indexerApi";

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

// --- /history paging (the client half of the { items, nextBefore } envelope) ------

test("a history page URL always carries limit, and before only when asked", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const first = new URL(buildHistoryPageUrl("http://localhost:8600", compressed, "tok.en"));
  assert.equal(first.pathname, "/history");
  assert.equal(first.searchParams.get("token"), "tok.en");
  // `limit` is what SELECTS the envelope over the legacy bare array, so the first
  // page must send it even though the server would default to the same number.
  assert.equal(first.searchParams.get("limit"), String(HISTORY_PAGE_LIMIT));
  assert.equal(first.searchParams.get("before"), null, "the newest page has no cursor");

  const next = new URL(buildHistoryPageUrl("http://localhost:8600", compressed, "tok.en", { before: 41, limit: 7 }));
  assert.equal(next.searchParams.get("before"), "41");
  assert.equal(next.searchParams.get("limit"), "7");

  // The deployed wallet reaches its indexer on a RELATIVE base ("/indexer"), which
  // `new URL` cannot parse — the builder must not have used it internally either.
  const relative = buildHistoryPageUrl("/indexer", compressed, "tok.en", { before: 3 });
  assert.ok(relative.startsWith("/indexer/history?owner="), relative);
  assert.ok(relative.includes("&before=3"), relative);
});

test("fetchHistoryPage round-trips the page envelope over an injected fetch", async () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const served: HistoryPage = {
    items: [
      { kind: "received", counterparty: null, amount: "5", txHash: "0xaa", blockTimestamp: 1, seq: 9 },
      { kind: "sent", counterparty: null, amount: "2", txHash: "0xbb", blockTimestamp: 1, seq: 8 },
    ],
    nextBefore: 8,
  };
  const requestedUrls: string[] = [];
  const fakeFetch = (async (url: string) => {
    requestedUrls.push(url);
    return { ok: true, text: async () => JSON.stringify(served) };
  }) as unknown as typeof fetch;

  const page = await fetchHistoryPage("http://localhost:8600", compressed, "tok.en", { before: 20, limit: 2 }, fakeFetch);
  const requested = requestedUrls[0] ?? "";
  assert.deepEqual(page, served, "the envelope is returned as-is, not flattened to an array");
  assert.ok(requested.includes("before=20") && requested.includes("limit=2"), requested);

  // A non-2xx keeps the shared error shape the wallet's classifyReadFailure reads
  // ("-> 401" is what sends the app back to onboarding).
  const denied = (async () => ({ ok: false, status: 401, text: async () => "nope" })) as unknown as typeof fetch;
  await assert.rejects(
    () => fetchHistoryPage("http://localhost:8600", compressed, "tok.en", {}, denied),
    /-> 401/,
  );
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

// --- name directory + announcements clients (fake-fetch round-trips) -------------
//
// These three are plain transport wrappers (no signing), so the whole client can
// be exercised headlessly: capture what was sent, serve a canned body, and check
// the parse + the error shape classifyIndexerRead reads.

const NAME_RECORD: NameRecord = {
  name: "alice",
  owner: "0x" + "11".repeat(32),
  viewPub: "0x" + "22".repeat(32),
  spendPub: "0x" + "33".repeat(33),
  updatedAt: 1_700_000_000,
};

/** A fake fetch that records every (url, init) and serves one canned response. */
function fakeFetch(status: number, body: string) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return { ok: status >= 200 && status < 300, status, text: async () => body };
  }) as unknown as typeof fetch;
  return { fn, calls };
}

test("normalizeName: canonical form is trim+lowercase; shape violations are null", () => {
  // trim + lowercase IS the canonicalization (the registry stores this form)…
  assert.equal(normalizeName("  PayRoll-Team "), "payroll-team");
  // …interior hyphens are part of the DNS-label shape…
  assert.equal(normalizeName("a-b-c"), "a-b-c");
  // …but a hyphen at either end, or a length outside 3..32, has no canonical form.
  for (const bad of ["-abc", "abc-", "ab", "a".repeat(33)]) {
    assert.equal(normalizeName(bad), null, `accepted: ${JSON.stringify(bad)}`);
  }
});

test("registerName POSTs the registration body verbatim and parses the accepted record", async () => {
  const reg: NameRegistration = {
    name: NAME_RECORD.name,
    owner: NAME_RECORD.owner,
    viewPub: NAME_RECORD.viewPub,
    spendPub: NAME_RECORD.spendPub,
    ts: 1_700_000_000,
    sig: "0x" + "44".repeat(64),
  };
  const { fn, calls } = fakeFetch(200, JSON.stringify(NAME_RECORD));
  const rec = await registerName("http://localhost:8600/", reg, fn);
  assert.deepEqual(rec, NAME_RECORD);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.url, "http://localhost:8600/names"); // trailing slash trimmed
  assert.equal(calls[0]?.init?.method, "POST");
  assert.deepEqual(calls[0]?.init?.headers, { "content-type": "application/json" });
  // The signature authorises EXACTLY this payload, so the body must be the
  // registration itself — no re-shaping between builder and wire.
  assert.equal(calls[0]?.init?.body, JSON.stringify(reg));
});

test("registerName throws the shared error shape with the server body on any error status", async () => {
  const reg = { name: "x", owner: "o", viewPub: "v", spendPub: "s", ts: 1, sig: "g" };
  const { fn } = fakeFetch(409, "name is taken");
  await assert.rejects(
    () => registerName("http://localhost:8600", reg, fn),
    /http:\/\/localhost:8600\/names -> 409: name is taken/,
  );
});

test("resolveName returns the record on 200 and null on 404, and throws on 500", async () => {
  const ok = fakeFetch(200, JSON.stringify(NAME_RECORD));
  assert.deepEqual(await resolveName("http://localhost:8600/", "alice", ok.fn), NAME_RECORD);
  // The name segment is URL-encoded, against a slash smuggling a different route.
  assert.equal(ok.calls[0]?.url, "http://localhost:8600/names/alice");
  const encoded = fakeFetch(404, "not found");
  await resolveName("http://localhost:8600", "a/b", encoded.fn);
  assert.equal(encoded.calls[0]?.url, "http://localhost:8600/names/a%2Fb");

  // 404 is an ANSWER (unregistered), not a failure.
  assert.equal(await resolveName("http://localhost:8600", "nobody", fakeFetch(404, "no such name").fn), null);

  // …but a real failure keeps the "-> <status>" shape classifyIndexerRead parses.
  await assert.rejects(
    () => resolveName("http://localhost:8600", "alice", fakeFetch(500, "boom").fn),
    /-> 500: boom/,
  );
});

test("getAnnouncements sends cursor/limit and parses the feed", async () => {
  const served: WithdrawAnnouncementRecord[] = [
    { seq: 7, txHash: "0xcc", blockNumber: 12, recipient: "0x" + "55".repeat(20), ephemeralPub: "0x" + "66".repeat(32), viewTag: 3 },
  ];
  const paged = fakeFetch(200, JSON.stringify(served));
  assert.deepEqual(await getAnnouncements("http://localhost:8600/", 41, 7, paged.fn), served);
  assert.equal(paged.calls[0]?.url, "http://localhost:8600/announcements?cursor=41&limit=7");

  // Defaults: cursor -1 (from the start) and the 5000 cap — the scan-all path.
  const defaults = fakeFetch(200, "[]");
  assert.deepEqual(await getAnnouncements("http://localhost:8600", undefined, undefined, defaults.fn), []);
  assert.equal(defaults.calls[0]?.url, "http://localhost:8600/announcements?cursor=-1&limit=5000");
});

// --- portal client half (fake-fetch round-trips, the names-client pattern) --------

import {
  payPortal,
  fetchUnswept,
  getPortalAnnouncements,
  type PortalIssuance,
  type PortalRecord,
} from "@bongtu/core/indexerApi";

const PORTAL_ISSUANCE: PortalIssuance = {
  destination: "0x" + "77".repeat(20),
  ephemeralPub: "0x" + "88".repeat(32),
  viewTag: 42,
  stealthAddr: "0x" + "99".repeat(20),
  factory: "0x" + "aa".repeat(20),
};

const PORTAL_RECORD: PortalRecord = {
  kind: "portal",
  seq: 3,
  name: "alice",
  owner: "0x" + "11".repeat(32),
  ephemeralPub: "0x" + "88".repeat(32),
  viewTag: 42,
  stealthAddr: "0x" + "99".repeat(20),
  destination: "0x" + "77".repeat(20),
  createdAt: 1_700_000_000,
  swept: false,
  sweptTxHash: null,
  sweptAmount: null,
};

test("payPortal POSTs to /pay/{name} and parses the issuance", async () => {
  const { fn, calls } = fakeFetch(200, JSON.stringify(PORTAL_ISSUANCE));
  const issued = await payPortal("http://localhost:8600/", "alice", fn);
  assert.deepEqual(issued, PORTAL_ISSUANCE);
  assert.equal(calls[0]?.url, "http://localhost:8600/pay/alice"); // trailing slash trimmed
  assert.equal(calls[0]?.init?.method, "POST");

  // The name segment is URL-encoded, against a slash smuggling a different route.
  const encoded = fakeFetch(404, "no such name");
  await assert.rejects(() => payPortal("http://localhost:8600", "a/b", encoded.fn), /-> 404: no such name/);
  assert.equal(encoded.calls[0]?.url, "http://localhost:8600/pay/a%2Fb");
});

test("payPortal keeps the shared error shape on the unconfigured-factory 404", async () => {
  const { fn } = fakeFetch(404, "portal deposits are not configured");
  await assert.rejects(
    () => payPortal("http://localhost:8600", "alice", fn),
    /http:\/\/localhost:8600\/pay\/alice -> 404: portal deposits are not configured/,
  );
});

test("fetchUnswept and getPortalAnnouncements send cursor/limit and parse the feed", async () => {
  const unswept = fakeFetch(200, JSON.stringify([PORTAL_RECORD]));
  assert.deepEqual(await fetchUnswept("http://localhost:8600/", 41, 7, unswept.fn), [PORTAL_RECORD]);
  assert.equal(unswept.calls[0]?.url, "http://localhost:8600/portal/unswept?cursor=41&limit=7");

  const announce = fakeFetch(200, JSON.stringify([PORTAL_RECORD]));
  assert.deepEqual(await getPortalAnnouncements("http://localhost:8600", 2, 3, announce.fn), [PORTAL_RECORD]);
  assert.equal(announce.calls[0]?.url, "http://localhost:8600/portal/announcements?cursor=2&limit=3");

  // Defaults: cursor -1 (from the start) and the 5000 cap, like getAnnouncements.
  const defaults = fakeFetch(200, "[]");
  assert.deepEqual(await fetchUnswept("http://localhost:8600", undefined, undefined, defaults.fn), []);
  assert.equal(defaults.calls[0]?.url, "http://localhost:8600/portal/unswept?cursor=-1&limit=5000");
});

// --- the bound IndexerClient (issue #15 C1) ---------------------------------------
//
// Interface-level gates for the class layer ONLY — every method delegates to the
// free functions above, whose protocol behavior the earlier suites already pin,
// so these cases cover exactly what the class ADDS: the constructor-bound seam,
// tear-off safety, the frozen error string surviving delegation, 404-as-answer,
// and the asOwner capability matrix at the type level.

import { IndexerClient } from "@bongtu/core/indexerApi";
import { classifyIndexerRead } from "@bongtu/core/errors";

test("IndexerClient routes every read through the constructor fetchFn, base trimmed once", async () => {
  const cases: { call: (c: IndexerClient) => Promise<unknown>; url: string }[] = [
    { call: (c) => c.head(), url: "http://localhost:8600/head" },
    { call: (c) => c.nullifiers(), url: "http://localhost:8600/nullifiers" },
    { call: (c) => c.events(41, 7), url: "http://localhost:8600/events?cursor=41&limit=7" },
    // the free-function defaults (cursor -1, the 5000 cap) still apply through
    // the delegation, so a bare tear-off call hits the same URL it always did.
    { call: (c) => c.unswept(), url: "http://localhost:8600/portal/unswept?cursor=-1&limit=5000" },
  ];
  for (const { call, url } of cases) {
    const { fn, calls } = fakeFetch(200, "[]");
    await call(new IndexerClient("http://localhost:8600/", { fetchFn: fn }));
    assert.equal(calls[0]?.url, url);
  }
});

test("a class read throws the frozen error string classifyIndexerRead parses", async () => {
  const client = new IndexerClient("http://localhost:8600", { fetchFn: fakeFetch(401, "expired token").fn });
  const err = await client.head().then(
    () => null,
    (e: Error) => e,
  );
  assert.equal(err?.message, "http://localhost:8600/head -> 401: expired token");
  assert.deepEqual(classifyIndexerRead(err), { kind: "unauthorized", status: 401 });
});

test("client.resolveName keeps 404-as-answer: null, not a throw", async () => {
  const client = new IndexerClient("http://localhost:8600", { fetchFn: fakeFetch(404, "no such name").fn });
  assert.equal(await client.resolveName("nobody"), null);
});

test("methods survive tear-off (arrow properties keep their instance)", async () => {
  const { fn, calls } = fakeFetch(200, JSON.stringify({ root: "1", nextLeafIndex: 0 }));
  const { head } = new IndexerClient("http://localhost:8600", { fetchFn: fn });
  assert.deepEqual(await head(), { root: "1", nextLeafIndex: 0 });
  assert.equal(calls[0]?.url, "http://localhost:8600/head");
});

test("asOwner encodes the capability matrix: signed /path is key-only, paged history token-only", () => {
  const kp = deriveKeypair(OWNER_SCALAR);
  const compressed = packPubkey(kp.publicKey);
  const client = new IndexerClient("http://localhost:8600", { fetchFn: fakeFetch(200, "[]").fn });
  const byToken = client.asOwner(compressed, { token: "tok.en" });
  const byKey = client.asOwner(compressed, { key: kp.formattedPrivateKey });
  // @ts-expect-error — a token cannot open a within-batch leaf: the server
  // requires the owner's signature there, so the type refuses before the 401.
  void byToken.signedPath;
  // @ts-expect-error — a key-mode binding is transient: nothing survives to
  // page a second request with, so paged history is token-only.
  void byKey.historyPage;
  assert.equal(typeof byToken.historyPage, "function");
  assert.equal(typeof byKey.signedPath, "function");
});
