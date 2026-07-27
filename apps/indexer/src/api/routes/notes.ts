import type { Route, RouteResult } from "../router.js";
import type { OwnerNote } from "@bongtu/core/indexerApi";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { notesAuthMessage, parseSignature, verifyNotesAuth } from "@bongtu/core/eddsa";
import type { Point } from "@bongtu/core/babyjub";

// SPEC §6b v2 `/notes?owner=<compressed>&ts=<unix>&sig=<hex>` — ARBITER MODE ONLY
// (registered by the router only when the indexer holds the arbiter key). Serves
// the arbiter's decrypted view of ONE owner's notes:
//   [{ value, salt, leafIndex, commitment, txHash, spent }].
//
// AUTH — ENFORCED (SPEC §6b v2). The auditor-key indexer decrypts every user's
// notes, so an unauthenticated /notes would expose everyone's payroll to anyone
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
const AUTH_HEADER = {
  "x-bongtu-auth":
    "ENFORCED (bjj EdDSA-Poseidon sig over Poseidon(ownerPub.x,ownerPub.y,ts), |now-ts|<=300s replay window, OR a /auth view token; SPEC §6b v2). Arbiter holds all notes by design.",
};

const WINDOW_SECONDS = 300; // replay window: |now - ts| must be within this

const bad = (body: unknown): RouteResult => ({ status: 400, body });
const unauthorized = (reason: string): RouteResult => ({ status: 401, body: { error: reason } });

export const notes: Route = {
  method: "GET",
  pattern: "/notes",
  handle({ ix, tokens, query }) {
    const owner = query.get("owner");
    if (!owner) {
      return bad({ error: "owner query param required: a compressed bjj pubkey (32-byte hex)" });
    }
    // owner is now a COMPRESSED pubkey — unpack to [x,y]. Malformed → 400.
    let pub: Point;
    try {
      pub = unpackPubkey(owner);
    } catch (e) {
      return bad({ error: `malformed compressed owner pubkey: ${(e as Error).message}`, owner });
    }

    // Auth path (b): a view token from POST /auth. Presence of `token` selects
    // this path exclusively — a bad token is a 401, never a silent fall-through
    // to ts/sig (that would let a stolen-token probe piggyback a replayed sig).
    const token = query.get("token");
    if (token !== null) {
      // No token service = no issuer, so no token can be genuine (public mode has
      // neither this route nor /auth; the guard keeps that a type-level fact).
      if (!tokens || !tokens.verifyToken(owner, token)) {
        return unauthorized("view token invalid or expired — re-authenticate via /auth");
      }
    } else {
      // Auth path (a): the signed query. Missing sig/ts is a malformed request
      // (400); a well-formed but failing auth is a 401. The auth check runs
      // BEFORE any ledger lookup so it never leaks whether the owner has notes.
      const sigHex = query.get("sig");
      const tsRaw = query.get("ts");
      if (!sigHex || !tsRaw) {
        return bad({ error: "auth required: query params ts (unix seconds) and sig (hex), or a token" });
      }
      const ts = Number(tsRaw);
      if (!Number.isInteger(ts)) {
        return bad({ error: "ts must be an integer number of unix seconds", ts: tsRaw });
      }
      let sig;
      try {
        sig = parseSignature(sigHex);
      } catch (e) {
        return bad({ error: `malformed sig: ${(e as Error).message}` });
      }

      // Replay window (server clock, in the ROUTE only — never in workflow scripts).
      const now = Math.floor(Date.now() / 1000);
      if (Math.abs(now - ts) > WINDOW_SECONDS) {
        return unauthorized(`timestamp outside the ${WINDOW_SECONDS}s replay window (|now-ts| too large)`);
      }

      // Signature must be over Poseidon(ownerPub.x, ownerPub.y, ts) and verify
      // against the queried pubkey — proving the caller owns the key.
      const msg = notesAuthMessage(pub, ts);
      if (!verifyNotesAuth(pub, msg, sig)) {
        return unauthorized("signature does not verify against the queried owner pubkey");
      }
    }

    if (!ix.ledger) {
      // Arbiter mode but ingest has not built the ledger yet (pre first ingest).
      return { status: 503, body: { error: "arbiter ledger not built yet" } };
    }
    // Wire shape owned by @bongtu/core/indexerApi (server-adapter typing).
    const body: OwnerNote[] = ix.ledger.notesOf(pub[0], pub[1]);
    return { status: 200, body, headers: AUTH_HEADER };
  },
};
