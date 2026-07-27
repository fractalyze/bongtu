import type { Route } from "../router.js";
import type { OwnerNote } from "@bongtu/core/indexerApi";
import { authorizeOwner, AUTH_HEADER } from "../readAuth.js";

// SPEC §6b v2 `/notes?owner=<compressed>&ts=<unix>&sig=<hex>` — ARBITER MODE ONLY
// (registered by the router only when the indexer holds the arbiter key). Serves
// the arbiter's decrypted view of ONE owner's notes:
//   [{ value, salt, leafIndex, commitment, txHash, spent }].
// The read-auth (signed query OR view token, ±300s replay window) is the one
// api/readAuth.ts owns and /history shares — this route only adds its projection.
export const notes: Route = {
  method: "GET",
  pattern: "/notes",
  handle(ctx) {
    const auth = authorizeOwner(ctx);
    if (!auth.ok) return auth.denied;

    if (!ctx.ix.ledger) {
      // Arbiter mode but ingest has not built the ledger yet (pre first ingest).
      return { status: 503, body: { error: "arbiter ledger not built yet" } };
    }
    // Wire shape owned by @bongtu/core/indexerApi (server-adapter typing).
    const body: OwnerNote[] = ctx.ix.ledger.notesOf(auth.pub[0], auth.pub[1]);
    return { status: 200, body, headers: AUTH_HEADER };
  },
};
