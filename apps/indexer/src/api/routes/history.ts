import type { Route } from "../router.js";
import type { HistoryItem } from "@bongtu/core/indexerApi";
import { authorizeOwner, AUTH_HEADER } from "../readAuth.js";

// SPEC §6b `/history?owner=<compressed>&ts=<unix>&sig=<hex>` — ARBITER MODE ONLY
// (registered by the router only when the indexer holds the arbiter key). Serves
// the arbiter's per-owner activity feed derived from the decrypted authority
// envelopes: [{ kind, counterparty, amount, txHash, blockTimestamp, seq }],
// newest-first. Same read-auth as /notes — literally the same api/readAuth.ts
// call (the arbiter-key indexer knows every user's activity, so an
// unauthenticated /history would expose everyone's payroll flow to anyone who can
// reach it); this route only adds its projection.
export const history: Route = {
  method: "GET",
  pattern: "/history",
  handle(ctx) {
    const auth = authorizeOwner(ctx);
    if (!auth.ok) return auth.denied;

    if (!ctx.ix.ledger) {
      // Arbiter mode but ingest has not built the ledger yet (pre first ingest).
      return { status: 503, body: { error: "arbiter ledger not built yet" } };
    }
    // Wire shape owned by @bongtu/core/indexerApi (server-adapter typing).
    const body: HistoryItem[] = ctx.ix.ledger.historyOf(auth.pub[0], auth.pub[1]);
    return { status: 200, body, headers: AUTH_HEADER };
  },
};
