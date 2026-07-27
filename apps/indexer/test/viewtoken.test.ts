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
//   4. ROUTES — /notes and /history accept EITHER auth (signed query unchanged —
//      old wallets/drivers keep working — or a token); a bad token is 401 and
//      never falls through to the sig path; a tokenless (public-mode) server
//      honours no token at all.

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
  VIEWTOKEN_DOMAIN_TAG,
} from "@bongtu/core/eddsa";
import {
  ViewTokenService,
  TOKEN_TTL_SECONDS,
  CHALLENGE_TTL_SECONDS,
  resolvePublicUrls,
} from "../src/api/viewtoken.js";
import { authChallenge, authRedeem } from "../src/api/routes/auth.js";
import { notes } from "../src/api/routes/notes.js";
import { history } from "../src/api/routes/history.js";
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

// ============================ (4) ROUTES =====================================

test("/notes and /history accept both auth paths; bad tokens 401 without sig fallback", () => {
  const svc = svcAt();
  const { challenge } = svc.issueChallenge(ownerCompressed);
  const issued = svc.redeemChallenge(ownerCompressed, challenge, signFor(OWNER, challenge, HOME));
  assert.ok(issued);

  for (const [route, item] of [
    [notes, FAKE_NOTE],
    [history, FAKE_HISTORY],
  ] as const) {
    // (a) the ORIGINAL signed query still works (backward compat).
    const signedUrl = new URL(buildNotesUrl("http://x", ownerCompressed, OWNER.formattedPrivateKey), "http://x");
    const signed = call(route, svc, signedUrl.searchParams.toString());
    assert.equal(signed.status, 200);
    assert.deepEqual(signed.body, [item]);

    // (b) the token path works with NO sig/ts at all.
    const tokenQ = `owner=${ownerCompressed}&token=${encodeURIComponent(issued.token)}`;
    const viaToken = call(route, svc, tokenQ);
    assert.equal(viaToken.status, 200);
    assert.deepEqual(viaToken.body, [item]);

    // wrong owner under a valid token -> 401.
    const wrongOwner = call(route, svc, `owner=${otherCompressed}&token=${encodeURIComponent(issued.token)}`);
    assert.equal(wrongOwner.status, 401);

    // tampered token -> 401 EVEN IF a valid sig rides along (no fall-through).
    const tampered = issued.token.slice(0, -1) + (issued.token.endsWith("0") ? "1" : "0");
    const mixed = call(route, svc, `${signedUrl.searchParams.toString()}&token=${encodeURIComponent(tampered)}`);
    assert.equal(mixed.status, 401);

    // token absent AND no sig/ts -> still the original 400.
    const bare = call(route, svc, `owner=${ownerCompressed}`);
    assert.equal(bare.status, 400);

    // a server with NO token service (public mode) honours no token, valid or not.
    const tokenless = call(route, null, tokenQ);
    assert.equal(tokenless.status, 401);
    // …and the signed query still works there, so the guard is token-path-only.
    assert.equal(call(route, null, signedUrl.searchParams.toString()).status, 200);
  }

  // the /auth endpoints refuse to pretend when there is no service behind them.
  assert.equal(call(authChallenge, null, `owner=${ownerCompressed}`).status, 503);
  assert.equal(call(authRedeem, null, "", { owner: ownerCompressed, challenge: "1", sig: "0x00" }).status, 503);
});
