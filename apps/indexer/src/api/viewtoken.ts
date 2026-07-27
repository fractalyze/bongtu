// View tokens for the arbiter read API (/notes + /history): a browser wallet that
// proved key ownership ONCE gets an opaque, expiring, HMAC-signed token so later
// balance/activity reads need no bjj private key at all. This is the server half
// of the wallet's login persistence: the ONLY credential a browser ever stores is
// this view-only token — nothing else in the system accepts it (it cannot spend,
// cannot disburse, cannot touch any write path; there is no write path).
//
// Flow (client half in @bongtu/core/indexerApi `obtainViewToken`):
//   1. GET  /auth/challenge?owner=<compressed> -> { challenge, expiresAt, hostBindings }
//      challenge = a random field element, held server-side, single-use, short TTL.
//   2. client signs Poseidon(ownerPub.x, ownerPub.y, challenge, hostBinding,
//      VIEWTOKEN_DOMAIN_TAG) with the owner bjj key (`viewTokenAuthMessage` in
//      @bongtu/core/eddsa) — the same EdDSA-Poseidon primitive the signed /notes
//      query uses, over a DIFFERENT, wider, domain-tagged preimage.
//   3. POST /auth  { owner, challenge, sig }  -> { token, exp }
//      token = "v1.<owner>.<exp>." + HMAC-SHA256(secret, owner || exp). The server
//      keeps NO token state: validity is the HMAC + the embedded expiry, so a
//      restart with the same TOKEN_SECRET keeps tokens alive, and a generated
//      (env-absent) secret invalidates them all — which is why boot warns.
//
// Three bindings carry the security, and each closes a distinct attack:
//   - CHALLENGE (a server-drawn nonce, not a client timestamp): a captured /auth
//     request cannot be replayed after the ~2-minute TTL, and the single-use
//     consume stops replay inside it.
//   - DOMAIN TAG + arity 5: a legacy `notesAuthMessage(pub, ts)` signature scraped
//     off a /notes URL can never verify here (and a challenge signature can never
//     pass as a /notes query) — without it the two are the same Poseidon shape and
//     one leaked read URL would buy a 24h token.
//   - HOST BINDING: the signed tuple names the indexer ORIGIN the client dialled.
//     A hostile indexer can proxy a real server's live challenge, but the victim
//     signs the HOSTILE origin's binding; redeeming that against the real server
//     verifies against the REAL binding and fails. Which is why the server checks
//     its OWN configured origins (PUBLIC_URL) and never a client-supplied one.

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { unpackPubkey } from "@bongtu/core/pubkey";
import {
  parseSignature,
  verifyNotesAuth,
  viewTokenAuthMessage,
  viewTokenHostBinding,
  CHALLENGE_BYTES,
} from "@bongtu/core/eddsa";

/** How long an issued token authorises reads (~24h — one working day per sign-in). */
export const TOKEN_TTL_SECONDS = 24 * 60 * 60;
/** How long a challenge stays redeemable (short: it only spans one round trip). */
export const CHALLENGE_TTL_SECONDS = 120;
/** Hard cap on live challenges. The TTL sweep alone is not a bound: a flood inside
 *  one TTL window can still add entries faster than they expire, so the map also
 *  evicts oldest-first at this ceiling. Unredeemed challenges are worthless, and
 *  a victim of eviction just re-fetches one. */
export const MAX_LIVE_CHALLENGES = 10_000;

const TOKEN_PREFIX = "v1";

/**
 * The HMAC secret: env TOKEN_SECRET verbatim, else a fresh random one per boot.
 * Generating warns because every token minted before the restart dies with the
 * old secret — harmless (wallets just re-auth) but worth a log line.
 */
export function resolveTokenSecret(env: Record<string, string | undefined> = process.env): Buffer {
  const raw = env.TOKEN_SECRET;
  if (raw && raw.trim() !== "") return Buffer.from(raw, "utf8");
  console.warn(
    "indexer: TOKEN_SECRET not set — generated a per-boot secret; issued view tokens reset on restart",
  );
  return randomBytes(32);
}

/** Canonical owner form the HMAC binds: trimmed, lowercased compressed-pubkey hex. */
function canonicalOwner(ownerCompressed: string): string {
  return ownerCompressed.trim().toLowerCase();
}

function hmacHex(secret: Buffer, owner: string, exp: number): string {
  return createHmac("sha256", secret).update(`${owner}|${exp}`).digest("hex");
}

/**
 * The origins clients are expected to reach this indexer on — what the host
 * bindings are derived from. `PUBLIC_URL` is a comma-separated list because ONE
 * indexer legitimately serves several wallet origins (custom domain + preview
 * deploys), and every entry is admin-chosen, so accepting any of them costs
 * nothing: a relaying attacker's origin is in none of them.
 *
 * The fallback is the loopback listen address, which is only right for a client
 * dialling the indexer DIRECTLY. The wallet normally reaches it through a
 * same-origin `/indexer` proxy, so the origin it signs is the PAGE's — meaning any
 * proxied deployment MUST set PUBLIC_URL to the wallet's origin(s) or logins fall
 * back to the tokenless path. The boot log prints what was resolved.
 */
export function resolvePublicUrls(
  env: Record<string, string | undefined> = process.env,
  port: number = Number(env.PORT || 8600),
): string[] {
  const configured = (env.PUBLIC_URL ?? "").split(",").map((u) => u.trim()).filter((u) => u !== "");
  if (configured.length > 0) return configured;
  return [`http://127.0.0.1:${port}`, `http://localhost:${port}`];
}

export interface IssuedChallenge {
  challenge: string; // decimal field element the client signs (with the owner pubkey)
  expiresAt: number; // unix seconds
  hostBindings: string[]; // origin digests this server accepts in the signed tuple
}

export interface IssuedToken {
  token: string;
  exp: number; // unix seconds
}

/**
 * Challenge issue/redeem + token mint/verify. One instance per API server; the
 * challenge map is in-memory on purpose (a challenge only spans one round trip —
 * losing it on restart just means the client re-fetches one).
 */
/** Everything but the HMAC secret, all defaulted — `now` and `maxChallenges` exist
 *  so expiry and the cap are testable without sleeping or issuing 10k challenges. */
export interface ViewTokenOptions {
  publicUrls?: string[];
  now?: () => number;
  maxChallenges?: number;
}

export class ViewTokenService {
  private readonly challenges = new Map<string, { owner: string; exp: number }>();
  /** The origin digests this server accepts in a signed tuple (PUBLIC_URL list). */
  readonly hostBindings: string[];
  private readonly now: () => number;
  private readonly maxChallenges: number;

  constructor(private readonly secret: Buffer, opts: ViewTokenOptions = {}) {
    const urls = opts.publicUrls ?? resolvePublicUrls();
    this.hostBindings = [...new Set(urls.map(viewTokenHostBinding))];
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.maxChallenges = opts.maxChallenges ?? MAX_LIVE_CHALLENGES;
  }

  /** Draw a fresh single-use challenge bound to `owner`. Throws on a malformed owner. */
  issueChallenge(ownerCompressed: string): IssuedChallenge {
    unpackPubkey(ownerCompressed.trim()); // malformed owner -> throw (route maps to 400)
    // CHALLENGE_BYTES is the SAME constant the client's assertValidChallenge
    // refuses beyond (@bongtu/core/eddsa), so the issuer can never draw a value
    // its own clients reject.
    let x = 0n;
    for (const b of randomBytes(CHALLENGE_BYTES)) x = (x << 8n) | BigInt(b);
    const challenge = (x === 0n ? 1n : x).toString();
    const exp = this.now() + CHALLENGE_TTL_SECONDS;
    this.sweep();
    this.evictToFit();
    this.challenges.set(challenge, { owner: canonicalOwner(ownerCompressed), exp });
    return { challenge, expiresAt: exp, hostBindings: this.hostBindings };
  }

  /**
   * Redeem a signed challenge into a token. Returns null (never throws) for an
   * unknown/expired/foreign challenge or a failing signature — the route turns
   * null into a single 401 so the reason never leaks which check failed.
   * The challenge is consumed on ANY redeem attempt (single-use).
   */
  redeemChallenge(ownerCompressed: string, challenge: string, sigHex: string): IssuedToken | null {
    const owner = canonicalOwner(ownerCompressed);
    const entry = this.challenges.get(challenge);
    this.challenges.delete(challenge); // single-use: burned whether or not it verifies
    if (!entry || entry.owner !== owner || entry.exp < this.now()) return null;
    let pub, sig;
    try {
      pub = unpackPubkey(owner);
      sig = parseSignature(sigHex);
    } catch {
      return null;
    }
    const bound = this.hostBindings.some((b) =>
      verifyNotesAuth(pub, viewTokenAuthMessage(pub, challenge, b), sig),
    );
    if (!bound) return null;
    const exp = this.now() + TOKEN_TTL_SECONDS;
    return { token: `${TOKEN_PREFIX}.${owner}.${exp}.${hmacHex(this.secret, owner, exp)}`, exp };
  }

  /**
   * Whether `token` currently authorises reads for `owner`. Constant-time MAC
   * compare; false (never throws) for malformed, expired, tampered, or
   * wrong-owner tokens.
   */
  verifyToken(ownerCompressed: string, token: string): boolean {
    const parts = token.split(".");
    if (parts.length !== 4 || parts[0] !== TOKEN_PREFIX) return false;
    const [, owner, expRaw, mac] = parts;
    if (owner !== canonicalOwner(ownerCompressed)) return false;
    const exp = Number(expRaw);
    if (!Number.isInteger(exp) || exp < this.now()) return false;
    const expected = hmacHex(this.secret, owner, exp);
    const a = Buffer.from(mac, "utf8");
    const b = Buffer.from(expected, "utf8");
    return a.length === b.length && timingSafeEqual(a, b);
  }

  /** Drop expired challenges so an unredeemed flood cannot grow the map forever. */
  private sweep(): void {
    const now = this.now();
    for (const [k, v] of this.challenges) if (v.exp < now) this.challenges.delete(k);
  }

  /** Make room for one more entry at the cap, oldest first (Map iterates in
   *  insertion order, which for a fixed TTL is also expiry order). */
  private evictToFit(): void {
    while (this.challenges.size >= this.maxChallenges) {
      const oldest = this.challenges.keys().next();
      if (oldest.done) return;
      this.challenges.delete(oldest.value);
    }
  }
}
