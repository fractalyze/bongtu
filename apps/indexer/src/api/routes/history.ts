import type { Route, RouteResult } from "../router.js";
import type { HistoryItem } from "@bongtu/core/indexerApi";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { notesAuthMessage, parseSignature, verifyNotesAuth } from "@bongtu/core/eddsa";
import type { Point } from "@bongtu/core/babyjub";

// SPEC §6b `/history?owner=<compressed>&ts=<unix>&sig=<hex>` — ARBITER MODE ONLY
// (registered by the router only when the indexer holds the arbiter key). Serves
// the arbiter's per-owner activity feed derived from the decrypted authority
// envelopes: [{ kind, counterparty, amount, txHash, blockTimestamp, seq }],
// newest-first. Same read-auth as /notes (the arbiter-key indexer knows every
// user's activity, so an unauthenticated /history would expose everyone's payroll
// flow to anyone who can reach it): the caller proves control of the queried key
// with a bjj EdDSA-Poseidon signature over Poseidon(ownerPub.x, ownerPub.y, ts),
// checked against the queried pubkey, inside a ±300s replay window. Malformed
// owner → 400; missing ts/sig → 400; wrong key or expired ts → 401.
// Like /notes, a `token=` view token (POST /auth, api/viewtoken.ts) is accepted
// in place of ts/sig — same dual-auth, same view-only scope.
const AUTH_HEADER = {
  "x-bongtu-auth":
    "ENFORCED (bjj EdDSA-Poseidon sig over Poseidon(ownerPub.x,ownerPub.y,ts), |now-ts|<=300s replay window, OR a /auth view token; SPEC §6b). Arbiter holds all activity by design.",
};

const WINDOW_SECONDS = 300; // replay window: |now - ts| must be within this

const bad = (body: unknown): RouteResult => ({ status: 400, body });
const unauthorized = (reason: string): RouteResult => ({ status: 401, body: { error: reason } });

export const history: Route = {
  method: "GET",
  pattern: "/history",
  handle({ ix, tokens, query }) {
    const owner = query.get("owner");
    if (!owner) {
      return bad({ error: "owner query param required: a compressed bjj pubkey (32-byte hex)" });
    }
    // owner is a COMPRESSED pubkey — unpack to [x,y]. Malformed → 400.
    let pub: Point;
    try {
      pub = unpackPubkey(owner);
    } catch (e) {
      return bad({ error: `malformed compressed owner pubkey: ${(e as Error).message}`, owner });
    }

    // Auth path (b): a view token — presence of `token` selects this path
    // exclusively (a bad token never falls through to ts/sig). Same rule as /notes.
    const token = query.get("token");
    if (token !== null) {
      // No token service = no issuer, so no token can be genuine (same rule as /notes).
      if (!tokens || !tokens.verifyToken(owner, token)) {
        return unauthorized("view token invalid or expired — re-authenticate via /auth");
      }
    } else {
      // Auth path (a): the signed query. Missing sig/ts is a malformed request
      // (400); a well-formed but failing auth is a 401. The auth check runs
      // BEFORE any ledger lookup so it never leaks whether the owner has activity.
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
    const body: HistoryItem[] = ix.ledger.historyOf(pub[0], pub[1]);
    return { status: 200, body, headers: AUTH_HEADER };
  },
};
