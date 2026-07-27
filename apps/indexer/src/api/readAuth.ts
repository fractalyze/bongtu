// The read-auth the two ARBITER-ONLY owner feeds share (SPEC §6b v2): /notes and
// /history ask the SAME question — "does this caller control the queried key?" —
// so they ask it in ONE place, and the routes differ only in the projection they
// serve afterwards.
//
// AUTH — ENFORCED. The auditor-key indexer decrypts every user's notes and
// activity, so an unauthenticated feed would expose everyone's payroll to anyone
// who can reach it. A caller must prove control of the queried key:
//   - `owner` is the COMPRESSED bjj pubkey (32-byte hex; see sdk/pubkey.ts). It is
//     unpacked to [x,y] for the ledger lookup; a malformed owner is a 400.
//   - `ts` is unix seconds; the request is rejected (401) unless |now - ts| <= 300s,
//     which bounds replay to a 5-minute window (server clock via Date.now()).
//   - `sig` is a bjj EdDSA-Poseidon signature over Poseidon(ownerPub.x, ownerPub.y,
//     ts), checked against the queried pubkey (sdk/eddsa.ts). A wrong key or a
//     tampered message fails the check → 401.
// The arbiter still holds every user's decrypted notes by design (that is the
// disclosure model); auth governs WHO may query, not what the arbiter can see. The
// arbiter PRIVATE key is never returned.
//
// TWO accepted proofs (either satisfies the auth, both key-gated at some point):
//   a) the original signed query (`ts` + `sig`, above) — kept verbatim so old
//      wallets and the e2e drivers keep working;
//   b) a view token (`token=` — issued by POST /auth after a signed challenge,
//      api/viewtoken.ts): lets a browser session read WITHOUT re-holding the bjj
//      key. The token is view-only by construction — only /notes and /history
//      accept it.
//
// The auth runs BEFORE any ledger lookup, so a rejected request never leaks
// whether the owner has notes or activity.

import type { RouteContext, RouteResult } from "./router.js";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { notesAuthMessage, parseSignature, verifyNotesAuth } from "@bongtu/core/eddsa";
import type { Point } from "@bongtu/core/babyjub";

/** The notice both feeds return: their auth is enforced, and what satisfies it. */
export const AUTH_HEADER = {
  "x-bongtu-auth":
    "ENFORCED (bjj EdDSA-Poseidon sig over Poseidon(ownerPub.x,ownerPub.y,ts), |now-ts|<=300s replay window, OR a /auth view token; SPEC §6b v2). Arbiter holds all notes and activity by design.",
};

const WINDOW_SECONDS = 300; // replay window: |now - ts| must be within this

const bad = (body: unknown): RouteResult => ({ status: 400, body });
const unauthorized = (reason: string): RouteResult => ({ status: 401, body: { error: reason } });

/** Either the proven owner pubkey, or the exact response the route must send instead. */
export type OwnerAuth = { ok: true; pub: Point } | { ok: false; denied: RouteResult };

/**
 * Authorise a read of ONE owner's feed. Returns the unpacked owner pubkey the
 * caller proved control of, or the ready-made 400/401 the route returns verbatim.
 *
 * `nowSeconds` is injectable so the replay-window BOUNDARY is testable
 * deterministically — a wall-clock boundary test drifts out of the window on a
 * slow CI runner (seconds pass between building the query and checking it).
 * Routes always use the default.
 */
export function authorizeOwner(
  { tokens, query }: RouteContext,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): OwnerAuth {
  const owner = query.get("owner");
  if (!owner) {
    return { ok: false, denied: bad({ error: "owner query param required: a compressed bjj pubkey (32-byte hex)" }) };
  }
  // owner is a COMPRESSED pubkey — unpack to [x,y]. Malformed → 400.
  let pub: Point;
  try {
    pub = unpackPubkey(owner);
  } catch (e) {
    return { ok: false, denied: bad({ error: `malformed compressed owner pubkey: ${(e as Error).message}`, owner }) };
  }

  // Auth path (b): a view token from POST /auth. Presence of `token` selects
  // this path exclusively — a bad token is a 401, never a silent fall-through
  // to ts/sig (that would let a stolen-token probe piggyback a replayed sig).
  const token = query.get("token");
  if (token !== null) {
    // No token service = no issuer, so no token can be genuine (public mode has
    // neither these routes nor /auth; the guard keeps that a type-level fact).
    if (!tokens || !tokens.verifyToken(owner, token)) {
      return { ok: false, denied: unauthorized("view token invalid or expired — re-authenticate via /auth") };
    }
    return { ok: true, pub };
  }

  // Auth path (a): the signed query. Missing sig/ts is a malformed request
  // (400); a well-formed but failing auth is a 401.
  const sigHex = query.get("sig");
  const tsRaw = query.get("ts");
  if (!sigHex || !tsRaw) {
    return { ok: false, denied: bad({ error: "auth required: query params ts (unix seconds) and sig (hex), or a token" }) };
  }
  const ts = Number(tsRaw);
  if (!Number.isInteger(ts)) {
    return { ok: false, denied: bad({ error: "ts must be an integer number of unix seconds", ts: tsRaw }) };
  }
  let sig;
  try {
    sig = parseSignature(sigHex);
  } catch (e) {
    return { ok: false, denied: bad({ error: `malformed sig: ${(e as Error).message}` }) };
  }

  // Replay window (server clock, in the ROUTE only — never in workflow scripts).
  const now = nowSeconds;
  if (Math.abs(now - ts) > WINDOW_SECONDS) {
    return { ok: false, denied: unauthorized(`timestamp outside the ${WINDOW_SECONDS}s replay window (|now-ts| too large)`) };
  }

  // Signature must be over Poseidon(ownerPub.x, ownerPub.y, ts) and verify
  // against the queried pubkey — proving the caller owns the key.
  const msg = notesAuthMessage(pub, ts);
  if (!verifyNotesAuth(pub, msg, sig)) {
    return { ok: false, denied: unauthorized("signature does not verify against the queried owner pubkey") };
  }
  return { ok: true, pub };
}
