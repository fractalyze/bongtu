import type { Route } from "../router.js";

// SPEC §6b v2 `/notes?owner=<x>,<y>` — ARBITER MODE ONLY (registered by the router
// only when the indexer holds the arbiter key). Serves the arbiter's decrypted
// view of ONE owner's notes: [{ value, salt, leafIndex, commitment, txHash, spent }].
// The owner param is a bjj pubkey as two field elements "x,y".
//
// AUTH — SECURITY MODEL, READ BEFORE EXPOSING THIS ENDPOINT: a bjj signature over
// sign(ownerPubKey ‖ timestamp), checked against the queried pubkey, is SPEC'd
// (§6b v2) so only the key owner reads their own notes — but its IMPLEMENTATION IS
// DEFERRED. v1 serves /notes UNAUTHENTICATED: since owner pubkeys are not secret,
// ANYONE who can reach this arbiter indexer can read ANY owner's full note history
// (value, salt, timing) by passing their pubkey. This endpoint is therefore an
// INSTITUTION-INTERNAL SERVICE ONLY — it MUST NOT be exposed on a public network
// until the bjj-signature check lands. (The arbiter already holds every user's
// decrypted notes by design; the auth gap is about who may query it, not new
// disclosure.) The arbiter PRIVATE key is never returned.
const AUTH_HEADER = {
  "x-bongtu-auth":
    "UNAUTHENTICATED (bjj-sig auth DEFERRED, SPEC §6b v2); any caller may read any owner — arbiter-internal use only",
};

export const notes: Route = {
  method: "GET",
  pattern: "/notes",
  handle({ ix, query }) {
    const owner = query.get("owner");
    if (!owner) {
      return { status: 400, body: { error: 'owner query param required: a bjj pubkey "x,y"' } };
    }
    const parts = owner.split(",");
    if (parts.length !== 2) {
      return { status: 400, body: { error: 'owner must be two field elements "x,y"', owner } };
    }
    let x: bigint;
    let y: bigint;
    try {
      x = BigInt(parts[0].trim());
      y = BigInt(parts[1].trim());
    } catch {
      return { status: 400, body: { error: "owner field elements must be integers", owner } };
    }
    if (!ix.ledger) {
      // Arbiter mode but ingest has not built the ledger yet (pre first ingest).
      return { status: 503, body: { error: "arbiter ledger not built yet" } };
    }
    return { status: 200, body: ix.ledger.notesOf(x, y), headers: AUTH_HEADER };
  },
};
