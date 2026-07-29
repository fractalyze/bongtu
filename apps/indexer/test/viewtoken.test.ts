// Headless gate for the view-token protocol (api/viewtoken.ts + the /auth routes +
// dual-auth on /notes and /history). No anvil, no Postgres: the ledger is a stub —
// what's under test is AUTH, not data.
//
//   1. SERVICE — challenge issue/redeem round-trip mints a verifying token;
//      expiry, tamper, wrong-owner, wrong-key, challenge replay all reject.
//   2. BINDINGS — the two properties the signed tuple exists for: a legacy
//      signed-query signature can never redeem (and vice versa), and a signature
//      bound to another origin can never redeem (challenge relay).
//   3. CLIENT LOOP — the sdk's `obtainViewToken` (the one client implementation)
//      driven against the real routes via a fake fetch yields a token the real
//      `verifyToken` accepts — closing the client/server loop in-process, the
//      same pattern indexerApi.test.ts uses for the signed query.
//   4. READ-AUTH — the matrix /notes and /history share (api/readAuth.ts): EITHER
//      auth is accepted (signed query unchanged — old wallets/drivers keep
//      working — or a token); a bad token is 401 and never falls through to the
//      sig path; a tokenless (public-mode) server honours no token at all. It
//      runs ONCE against the extracted function, and each route then only has to
//      prove it honours the verdict and serves its own projection.
//   5. ROUTES — /notes and /history honour the verdict; 503 pre-ledger.
//   6. PATH GATE — /path stays auth-free for single-append leaves but demands
//      the same read-auth PLUS leaf ownership for a within-batch leaf (whose
//      siblings are other recipients' commitments, servable only in arbiter
//      mode): unauthenticated 400/401, authenticated-but-not-the-owner 403.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import {
  obtainViewToken,
  buildNotesUrl,
  buildNotesTokenUrl,
  buildHistoryTokenUrl,
  viewTokenHostBinding,
} from "@bongtu/core/indexerApi";
import {
  notesAuthMessage,
  viewTokenAuthMessage,
  signNotesAuth,
  packSignature,
  assertValidChallenge,
  VIEWTOKEN_DOMAIN_TAG,
  CHALLENGE_BYTES,
} from "@bongtu/core/eddsa";
import { authorizeOwner, type OwnerAuth } from "../src/api/readAuth.js";
import {
  ViewTokenService,
  TOKEN_TTL_SECONDS,
  CHALLENGE_TTL_SECONDS,
  resolvePublicUrls,
} from "../src/api/viewtoken.js";
import { authChallenge, authRedeem } from "../src/api/routes/auth.js";
import { notes } from "../src/api/routes/notes.js";
import { history } from "../src/api/routes/history.js";
import { path as pathRoute } from "../src/api/routes/path.js";
import type { Indexer } from "../src/ingest.js";
import type { RouteContext, RouteResult } from "../src/api/router.js";

const OWNER = deriveKeypair(123456789123456789n);
const OTHER = deriveKeypair(987654321987654321n);
const ownerCompressed = packPubkey(OWNER.publicKey);
const otherCompressed = packPubkey(OTHER.publicKey);

const SECRET = Buffer.from("test-secret-please-ignore");
const HOME = "https://wallet.example";
const HOSTILE = "https://evil.example";

/** A service on HOME, so every signature below binds to a known origin. */
const svcAt = (opts: { now?: () => number; maxChallenges?: number; urls?: string[] } = {}): ViewTokenService =>
  new ViewTokenService(SECRET, {
    publicUrls: opts.urls ?? [HOME],
    now: opts.now,
    maxChallenges: opts.maxChallenges,
  });

/** Sign a challenge the way the real client does, for an arbitrary origin. */
const signFor = (kp: typeof OWNER, challenge: string, origin: string): string =>
  packSignature(
    signNotesAuth(kp.formattedPrivateKey, viewTokenAuthMessage(kp.publicKey, BigInt(challenge), viewTokenHostBinding(origin))),
  );

// A movable clock so expiry is tested without sleeping.
function clock(start: number): { now: () => number; advance: (s: number) => void } {
  let t = start;
  return { now: () => t, advance: (s) => (t += s) };
}

// The routes only touch arbiterMode + ledger.{notesOf,historyOf}; a stub Indexer
// is enough — auth runs BEFORE any ledger access.
const FAKE_NOTE = { owner: ["1", "2"], value: "7", salt: "8", leafIndex: 0, commitment: "9", txHash: "0xab", spent: false };
const FAKE_HISTORY = { kind: "deposit", counterparty: null, amount: "7", txHash: "0xab", blockTimestamp: 1, seq: 1 };
const fakeIx = {
  arbiterMode: true,
  ledger: { notesOf: () => [FAKE_NOTE], historyOf: () => [FAKE_HISTORY] },
} as unknown as Indexer;

function call(
  route: { handle: (ctx: RouteContext) => RouteResult },
  tokens: ViewTokenService | null,
  query: string,
  body?: unknown,
): RouteResult {
  return route.handle({ ix: fakeIx, tokens, params: [], query: new URLSearchParams(query), body });
}

// ============================ (1) SERVICE ====================================

test("challenge round-trip mints a token that verifies for its owner", () => {
  const c = clock(1_000_000);
  const svc = svcAt({ now: c.now });
  const { challenge, expiresAt, hostBindings } = svc.issueChallenge(ownerCompressed);
  assert.ok(expiresAt === c.now() + CHALLENGE_TTL_SECONDS);
  assert.deepEqual(hostBindings, [viewTokenHostBinding(HOME)], "the challenge advertises the server's origins");

  const issued = svc.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOME));
  assert.ok(issued, "redeem returned null for a valid signature");
  assert.equal(issued.exp, c.now() + TOKEN_TTL_SECONDS);
  assert.equal(svc.verifyToken(ownerCompressed, issued.token), true);
  // view-only + owner-scoped: a different owner cannot use it.
  assert.equal(svc.verifyToken(otherCompressed, issued.token), false);
});

test("token expiry, tamper, wrong-owner and cross-secret all reject", () => {
  const c = clock(2_000_000);
  const svc = svcAt({ now: c.now });
  const { challenge } = svc.issueChallenge(ownerCompressed);
  const issued = svc.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOME));
  assert.ok(issued);

  // expiry: valid until TTL, dead after.
  c.advance(TOKEN_TTL_SECONDS - 1);
  assert.equal(svc.verifyToken(ownerCompressed, issued.token), true);
  c.advance(2);
  assert.equal(svc.verifyToken(ownerCompressed, issued.token), false);

  // tamper: flip the exp inside the token (HMAC no longer matches).
  const parts = issued.token.split(".");
  const tampered = [parts[0], parts[1], String(Number(parts[2]) + 100000), parts[3]].join(".");
  const svc2 = svcAt({ now: () => 2_000_000 });
  assert.equal(svc2.verifyToken(ownerCompressed, tampered), false);
  // tamper: flip a MAC hex char.
  const macFlip = issued.token.slice(0, -1) + (issued.token.endsWith("0") ? "1" : "0");
  assert.equal(svc2.verifyToken(ownerCompressed, macFlip), false);
  // a token minted under a DIFFERENT secret (e.g. after a secretless restart) dies.
  const svc3 = new ViewTokenService(Buffer.from("another-secret"), { publicUrls: [HOME], now: () => 2_000_000 });
  assert.equal(svc3.verifyToken(ownerCompressed, issued.token), false);
  // garbage shapes never throw.
  assert.equal(svc2.verifyToken(ownerCompressed, ""), false);
  assert.equal(svc2.verifyToken(ownerCompressed, "v1.x.y"), false);
});

test("challenge is single-use, owner-bound, key-checked and expires", () => {
  const c = clock(3_000_000);
  const svc = svcAt({ now: c.now });

  // wrong key: OTHER signs OWNER's challenge -> reject (and the challenge burns).
  const c1 = svc.issueChallenge(ownerCompressed);
  const wrongKeySig = packSignature(
    signNotesAuth(
      OTHER.formattedPrivateKey,
      viewTokenAuthMessage(OWNER.publicKey, BigInt(c1.challenge), viewTokenHostBinding(HOME)),
    ),
  );
  assert.equal(svc.redeemChallenge(ownerCompressed, c1.challenge, wrongKeySig), null);
  // single-use: even the RIGHT signature is refused after the burn.
  assert.equal(svc.redeemChallenge(ownerCompressed, c1.challenge, signFor(OWNER, c1.challenge, HOME)), null);

  // owner-bound: a challenge issued to OWNER cannot be redeemed as OTHER.
  const c2 = svc.issueChallenge(ownerCompressed);
  assert.equal(svc.redeemChallenge(otherCompressed, c2.challenge, signFor(OTHER, c2.challenge, HOME)), null);

  // expired challenge: past the TTL, a perfect signature is refused.
  const c3 = svc.issueChallenge(ownerCompressed);
  c.advance(CHALLENGE_TTL_SECONDS + 1);
  assert.equal(svc.redeemChallenge(ownerCompressed, c3.challenge, signFor(OWNER, c3.challenge, HOME)), null);
});

test("live challenges are capped, evicting oldest first", () => {
  const svc = svcAt({ maxChallenges: 4 });
  const issued = Array.from({ length: 6 }, () => svc.issueChallenge(ownerCompressed).challenge);
  // The two oldest were evicted to stay under the cap: their signatures no longer redeem.
  for (const gone of issued.slice(0, 2)) {
    assert.equal(svc.redeemChallenge(ownerCompressed, gone, signFor(OWNER, gone, HOME)), null);
  }
  // The newest still redeems, so the cap evicts rather than wedging the service.
  const newest = issued[issued.length - 1];
  assert.ok(svc.redeemChallenge(ownerCompressed, newest, signFor(OWNER, newest, HOME)));
});

test("resolvePublicUrls: PUBLIC_URL list wins, loopback listen address is the fallback", () => {
  assert.deepEqual(resolvePublicUrls({ PUBLIC_URL: " https://a.example , https://b.example " }, 8600), [
    "https://a.example",
    "https://b.example",
  ]);
  assert.deepEqual(resolvePublicUrls({}, 1234), ["http://127.0.0.1:1234", "http://localhost:1234"]);
  assert.deepEqual(resolvePublicUrls({ PUBLIC_URL: "   " }, 1234), ["http://127.0.0.1:1234", "http://localhost:1234"]);
});

// ============================ (2) BINDINGS ===================================

test("VIEWTOKEN_DOMAIN_TAG is the pinned ascii constant both halves compile in", () => {
  let expected = 0n;
  for (const b of new TextEncoder().encode("bongtu/viewtoken/v1")) expected = (expected << 8n) | BigInt(b);
  assert.equal(VIEWTOKEN_DOMAIN_TAG, expected);
  assert.notEqual(VIEWTOKEN_DOMAIN_TAG, 0n);
});

test("legacy /notes signatures and challenge signatures never cross over", () => {
  const svc = svcAt();

  // (a) a LEGACY-shaped signature — Poseidon(pub.x, pub.y, challenge), exactly what
  // the pre-domain-tag client sent, and exactly the shape of a /notes query signature
  // scraped off a URL — must not redeem for a 24h token.
  const legacy = svc.issueChallenge(ownerCompressed);
  const legacySig = packSignature(
    signNotesAuth(OWNER.formattedPrivateKey, notesAuthMessage(OWNER.publicKey, BigInt(legacy.challenge))),
  );
  assert.equal(svc.redeemChallenge(ownerCompressed, legacy.challenge, legacySig), null);

  // (b) the reverse: a genuine challenge signature replayed as a /notes signed query
  // (ts = the challenge) must not authorise the read either.
  const live = svc.issueChallenge(ownerCompressed);
  const challengeSig = signFor(OWNER, live.challenge, HOME);
  const confused = call(notes, svc, `owner=${ownerCompressed}&ts=${live.challenge}&sig=${challengeSig}`);
  assert.equal(confused.status, 401);
});

test("a signature bound to another origin never redeems (challenge relay)", () => {
  const real = svcAt(); // serves HOME
  const { challenge } = real.issueChallenge(ownerCompressed);

  // The victim's browser is talking to HOSTILE, which proxied this live challenge,
  // so the victim signs the HOSTILE binding. Relayed back, the real server rejects.
  assert.equal(real.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOSTILE)), null);

  // Control: the same challenge signed for the real origin does redeem, so the
  // rejection above is the binding and not an unrelated failure.
  const fresh = real.issueChallenge(ownerCompressed);
  assert.ok(real.redeemChallenge(ownerCompressed, fresh.challenge, signFor(OWNER, fresh.challenge, HOME)));
});

test("a multi-origin PUBLIC_URL accepts a signature bound to any configured origin", () => {
  const svc = svcAt({ urls: [HOME, "https://preview.example"] });
  const a = svc.issueChallenge(ownerCompressed);
  assert.ok(svc.redeemChallenge(ownerCompressed, a.challenge, signFor(OWNER, a.challenge, HOME)));
  const b = svc.issueChallenge(ownerCompressed);
  assert.ok(svc.redeemChallenge(ownerCompressed, b.challenge, signFor(OWNER, b.challenge, "https://preview.example")));
  const c = svc.issueChallenge(ownerCompressed);
  assert.equal(svc.redeemChallenge(ownerCompressed, c.challenge, signFor(OWNER, c.challenge, HOSTILE)), null);
});

// ============================ (3) CLIENT LOOP ================================

/** A fetch that dispatches to the REAL route handlers of `svc` — the wire shapes
 *  (param names, JSON body fields) are exactly what the browser sends. */
function routeFetch(svc: ViewTokenService, override?: (body: unknown) => unknown): typeof fetch {
  return (async (url: string, init?: { method?: string; body?: string }) => {
    const u = new URL(url, "http://localhost");
    const result =
      init?.method === "POST"
        ? call(authRedeem, svc, "", JSON.parse(init.body ?? "null"))
        : call(authChallenge, svc, u.searchParams.toString());
    const body = init?.method === "POST" ? result.body : (override?.(result.body) ?? result.body);
    return new Response(JSON.stringify(body), { status: result.status });
  }) as unknown as typeof fetch;
}

test("sdk obtainViewToken against the real routes yields an accepted token", async () => {
  const svc = svcAt({ urls: ["http://localhost:8600"] });
  const vt = await obtainViewToken("http://localhost:8600", ownerCompressed, OWNER.formattedPrivateKey, routeFetch(svc));
  assert.ok(vt.token.length > 0 && vt.exp > Math.floor(Date.now() / 1000));
  assert.equal(svc.verifyToken(ownerCompressed, vt.token), true);

  // and the token-URL builders emit the params the routes read.
  const nu = new URL(buildNotesTokenUrl("http://x", ownerCompressed, vt.token), "http://x");
  assert.equal(nu.pathname, "/notes");
  assert.equal(nu.searchParams.get("token"), vt.token);
  const hu = new URL(buildHistoryTokenUrl("http://x", ownerCompressed, vt.token), "http://x");
  assert.equal(hu.pathname, "/history");
});

test("the client refuses to sign a malformed or out-of-range challenge", async () => {
  const svc = svcAt({ urls: ["http://localhost:8600"] });
  for (const bogus of ["0", "-5", "12ab", "0x41", "1".repeat(80)]) {
    await assert.rejects(
      obtainViewToken(
        "http://localhost:8600",
        ownerCompressed,
        OWNER.formattedPrivateKey,
        routeFetch(svc, (b) => ({ ...(b as object), challenge: bogus })),
      ),
      /malformed challenge|out-of-range challenge/,
      `challenge ${JSON.stringify(bogus)} must be refused before signing`,
    );
  }
});

test("the client refuses a server that does not accept its origin", async () => {
  // The server's PUBLIC_URL names an origin no client actually dials — the wallet
  // must say so, not sign a tuple destined for a 401.
  const svc = svcAt({ urls: ["https://somewhere-else.example"] });
  await assert.rejects(
    obtainViewToken("http://localhost:8600", ownerCompressed, OWNER.formattedPrivateKey, routeFetch(svc)),
    /does not accept the origin/,
  );
});

test("end-to-end relay: a hostile indexer proxying a live challenge gains nothing", async () => {
  const real = svcAt({ urls: [HOME] });
  // The hostile server hands out the REAL server's challenge but advertises its own
  // origin — which is what the victim's browser computes, so the client signs it.
  const hostileFetch = (async (url: string, init?: { method?: string; body?: string }) => {
    if (init?.method === "POST") return new Response(JSON.stringify({ token: "ignored", exp: 0 }), { status: 200 });
    const proxied = real.issueChallenge(ownerCompressed);
    return new Response(
      JSON.stringify({ ...proxied, hostBindings: [viewTokenHostBinding(HOSTILE)] }),
      { status: 200 },
    );
  }) as unknown as typeof fetch;

  // The victim completes the handshake against the hostile host without complaint…
  const captured: { challenge?: string; sig?: string } = {};
  await obtainViewToken(HOSTILE, ownerCompressed, OWNER.formattedPrivateKey, (async (url: string, init?: { method?: string; body?: string }) => {
    if (init?.method === "POST") Object.assign(captured, JSON.parse(init.body ?? "{}"));
    return hostileFetch(url, init);
  }) as unknown as typeof fetch);

  // …and the captured signature is worthless at the real server.
  assert.ok(captured.challenge && captured.sig);
  assert.equal(real.redeemChallenge(ownerCompressed, captured.challenge, captured.sig), null);
});

// ============================ (4) READ-AUTH ==================================

/** Drive the shared read-auth exactly as the router hands it to a route. */
const authorize = (tokens: ViewTokenService | null, query: string, nowSeconds?: number): OwnerAuth =>
  authorizeOwner({ ix: fakeIx, tokens, params: [], query: new URLSearchParams(query) }, nowSeconds);

/** "ok" or the status the caller would have sent — the whole verdict in one value. */
const verdict = (a: OwnerAuth): number | "ok" => (a.ok ? "ok" : a.denied.status);

/** A signed query with an arbitrary signer and ts (the client builder always uses
 *  the owner's own key and "now", which is only the happy path). */
const signedQuery = (signer: typeof OWNER, ts: number): string =>
  `owner=${ownerCompressed}&ts=${ts}&sig=${packSignature(
    signNotesAuth(signer.formattedPrivateKey, notesAuthMessage(OWNER.publicKey, ts)),
  )}`;

test("read-auth: both proofs are accepted and every failing shape keeps its status", () => {
  const svc = svcAt();
  const { challenge } = svc.issueChallenge(ownerCompressed);
  const issued = svc.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOME));
  assert.ok(issued);
  const tokenQ = `owner=${ownerCompressed}&token=${encodeURIComponent(issued.token)}`;
  const signedQ = new URL(buildNotesUrl("http://x", ownerCompressed, OWNER.formattedPrivateKey), "http://x")
    .searchParams.toString();
  const now = Math.floor(Date.now() / 1000);
  const tampered = issued.token.slice(0, -1) + (issued.token.endsWith("0") ? "1" : "0");

  // (a) the ORIGINAL signed query still authorises (backward compat), and the
  // proven pubkey is the queried owner's — what the route looks the ledger up by.
  const signed = authorize(svc, signedQ);
  assert.equal(verdict(signed), "ok");
  assert.deepEqual(signed.ok && signed.pub, OWNER.publicKey);

  // (b) the token path authorises with NO sig/ts at all.
  assert.equal(verdict(authorize(svc, tokenQ)), "ok");

  // malformed REQUESTS are 400s, failing AUTH is a 401 — the split a client
  // distinguishes "fix your URL" from "prove who you are" by.
  assert.equal(verdict(authorize(svc, "")), 400, "no owner param");
  assert.equal(verdict(authorize(svc, "owner=abc&ts=1&sig=0x00")), 400, "malformed compressed owner");
  assert.equal(verdict(authorize(svc, `owner=${ownerCompressed}`)), 400, "no token and no ts/sig");
  assert.equal(verdict(authorize(svc, `owner=${ownerCompressed}&ts=1.5&sig=0x00`)), 400, "ts not integer seconds");
  assert.equal(verdict(authorize(svc, `owner=${ownerCompressed}&ts=${now}&sig=0xzz`)), 400, "malformed sig");
  assert.equal(verdict(authorize(svc, signedQuery(OTHER, now))), 401, "signature by the wrong key");
  // Window BOUNDARY with an injected clock — a wall-clock version drifts out of
  // the window on a slow runner (this exact test flaked on CI before injection).
  assert.equal(verdict(authorize(svc, signedQuery(OWNER, now - 301), now)), 401, "ts one second outside the 300s replay window");
  assert.equal(verdict(authorize(svc, signedQuery(OWNER, now - 300), now)), "ok", "…and the boundary second still passes");
  assert.equal(
    verdict(authorize(svc, `owner=${otherCompressed}&token=${encodeURIComponent(issued.token)}`)),
    401,
    "valid token, other owner",
  );

  // a bad token is terminal: presence of `token` selects that path exclusively,
  // so a valid sig riding along must NOT rescue the request.
  assert.equal(verdict(authorize(svc, `${signedQ}&token=${encodeURIComponent(tampered)}`)), 401);

  // a server with NO token service (public mode) honours no token, valid or not…
  assert.equal(verdict(authorize(null, tokenQ)), 401);
  // …while the signed query still works there, so the guard is token-path-only.
  assert.equal(verdict(authorize(null, signedQ)), "ok");
});

test("the issuer draws exactly the width the client's refusal bound allows", () => {
  // ONE constant owns both halves (eddsa.ts): the indexer's randomBytes width and
  // the client's out-of-range check. A drift here is a wallet that refuses to sign
  // a challenge its own server drew.
  const svc = svcAt();
  const { challenge } = svc.issueChallenge(ownerCompressed);
  assert.equal(assertValidChallenge(challenge), BigInt(challenge));
  const widest = (1n << BigInt(8 * CHALLENGE_BYTES)) - 1n;
  assert.equal(assertValidChallenge(widest.toString()), widest);
  assert.throws(() => assertValidChallenge((widest + 1n).toString()), /out-of-range/);
});

// ============================ (5) ROUTES =====================================

test("/notes and /history honour the auth verdict and serve their own projection", () => {
  const svc = svcAt();
  const { challenge } = svc.issueChallenge(ownerCompressed);
  const issued = svc.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOME));
  assert.ok(issued);
  const signedQ = new URL(buildNotesUrl("http://x", ownerCompressed, OWNER.formattedPrivateKey), "http://x")
    .searchParams.toString();

  for (const [route, item] of [
    [notes, FAKE_NOTE],
    [history, FAKE_HISTORY],
  ] as const) {
    for (const q of [signedQ, `owner=${ownerCompressed}&token=${encodeURIComponent(issued.token)}`]) {
      const served = call(route, svc, q);
      assert.equal(served.status, 200);
      assert.deepEqual(served.body, [item], "the authorized request reaches the ledger");
      assert.match(served.headers?.["x-bongtu-auth"] ?? "", /ENFORCED/);
    }
    // a denial is returned verbatim, not swallowed into a 200 with an empty body.
    assert.equal(call(route, svc, `owner=${ownerCompressed}`).status, 400);
  }
});

test("/notes and /history 503 while the arbiter ledger is still unbuilt", () => {
  const preIngest = { arbiterMode: true, ledger: null } as unknown as Indexer;
  const svc = svcAt();
  const signedQ = new URL(buildNotesUrl("http://x", ownerCompressed, OWNER.formattedPrivateKey), "http://x")
    .searchParams.toString();
  for (const route of [notes, history]) {
    const r = route.handle({ ix: preIngest, tokens: svc, params: [], query: new URLSearchParams(signedQ) });
    assert.equal(r.status, 503);
  }
});

test("the /auth endpoints refuse to pretend when there is no service behind them", () => {
  assert.equal(call(authChallenge, null, `owner=${ownerCompressed}`).status, 503);
  assert.equal(call(authRedeem, null, "", { owner: ownerCompressed, challenge: "1", sig: "0x00" }).status, 503);
});

// ============================ (6) PATH GATE ==================================

// /path serves single-append leaves to ANYONE (their siblings are recomputable
// from public chain data), but a REAL path into a disburse batch exists only in
// arbiter mode and its low levels are other recipients' commitments — so that
// read demands the shared read-auth PLUS ownership of the queried leaf.
test("/path gates a within-batch leaf behind read-auth + leaf ownership", () => {
  const svc = svcAt();
  // Leaves 0..3 are single-append; leaves 4..7 are an arbiter-filled batch
  // (isBatch on block 1). OWNER holds leaf 5 in the ledger; nobody holds 6.
  const pathIx = {
    arbiterMode: true,
    ledger: {
      notesOf: (x: bigint, y: bigint) =>
        x === OWNER.publicKey[0] && y === OWNER.publicKey[1] ? [{ ...FAKE_NOTE, leafIndex: 5 }] : [],
    },
    tree: {
      B: 4,
      nextLeafIndex: () => 8,
      isBatch: (k: number) => k === 1,
      path: () => ({ siblings: [1n, 2n, 3n], pathIndices: [0, 1, 0], root: 42n }),
    },
  } as unknown as Indexer;
  const at = (leafIndex: number, query: string): RouteResult =>
    pathRoute.handle({ ix: pathIx, tokens: svc, params: [String(leafIndex)], query: new URLSearchParams(query) });

  const signedQ = new URL(buildNotesUrl("http://x", ownerCompressed, OWNER.formattedPrivateKey), "http://x")
    .searchParams.toString();
  const { challenge } = svc.issueChallenge(ownerCompressed);
  const issued = svc.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOME));
  assert.ok(issued);
  const tokenQ = `owner=${ownerCompressed}&token=${encodeURIComponent(issued.token)}`;

  // A single-append leaf needs no auth at all — parity with a public indexer.
  const free = at(1, "");
  assert.equal(free.status, 200);
  assert.equal(free.headers?.["x-bongtu-auth"], undefined, "no enforced-auth notice on the ungated read");

  // The batch leaf refuses the very same unauthenticated request…
  assert.equal(at(5, "").status, 400, "no owner param");
  assert.equal(at(5, `owner=${ownerCompressed}`).status, 400, "no token and no ts/sig");
  const now = Math.floor(Date.now() / 1000);
  assert.equal(at(5, signedQuery(OTHER, now)).status, 401, "signature by the wrong key");

  // …and serves the proven owner through EITHER proof, with the enforced notice.
  for (const q of [signedQ, tokenQ]) {
    const served = at(5, q);
    assert.equal(served.status, 200);
    assert.deepEqual(served.body, { leafIndex: 5, siblings: ["1", "2", "3"], pathIndices: [0, 1, 0], root: "42" });
    assert.match(served.headers?.["x-bongtu-auth"] ?? "", /ENFORCED/);
  }

  // Proven — but not the holder of THIS leaf: a recipient may open its own batch
  // slot, never a neighbour's.
  assert.equal(at(6, signedQ).status, 403);
  assert.equal(at(6, tokenQ).status, 403);
});
