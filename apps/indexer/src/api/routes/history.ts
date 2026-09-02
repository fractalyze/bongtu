import type { Route } from "../router.js";
import type { HistoryItem, HistoryPage } from "@bongtu/core/indexerApi";
import { authorizeOwner, AUTH_HEADER } from "../readAuth.js";

// SPEC §6b `/history?owner=<compressed>&ts=<unix>&sig=<hex>` — ARBITER MODE ONLY
// (registered by the router only when the indexer holds the arbiter key). Serves
// the arbiter's per-owner activity feed derived from the decrypted authority
// envelopes: [{ kind, counterparty, amount, txHash, blockTimestamp, seq }],
// newest-first. Same read-auth as /notes — literally the same api/readAuth.ts
// call (the arbiter-key indexer knows every user's activity, so an
// unauthenticated /history would expose everyone's payroll flow to anyone who can
// reach it); this route only adds its projection.
//
// PAGING (`limit` + `before`). A long-lived payroll account's feed grows without
// bound, and serving all of it on every wallet refresh makes the client download
// its whole history to render four rows on Home. `before` is an EXCLUSIVE upper
// bound on `seq`, which is what makes the cursor stable: seq is assigned once, in
// chain-apply order, and never renumbered, so a page taken while new activity
// lands ahead of it returns the same rows — unlike an offset, which would shift
// under the insertions. `nextBefore` is the last served item's seq when the page
// came back FULL, and null once the feed is exhausted.

/** Matches the wallet's own default (core `HISTORY_PAGE_LIMIT`) so a client that
 *  sends only `before` keeps its page size. */
export const DEFAULT_LIMIT = 50;
/** A page is a render budget, not a bulk export: an unbounded `limit` would put
 *  the pre-paging cost back with none of the compat story. */
export const MAX_LIMIT = 200;

/** Parse a decimal non-negative integer param, or null when it is anything else.
 *  Digits-only rather than `Number()`, which quietly turns "" into 0, " 5 " into
 *  5 and "0x10" into 16 — a client sending any of those has a bug, and a paging
 *  param that means something other than what was typed is the worst way to find
 *  out. Above 2^53 is refused too: seq is a JS number and would stop being exact. */
function wholeNumber(raw: string): number | null {
  if (!/^\d+$/.test(raw)) return null;
  const n = Number(raw);
  return Number.isSafeInteger(n) ? n : null;
}

export const history: Route = {
  method: "GET",
  pattern: "/history",
  handle(ctx) {
    const auth = authorizeOwner(ctx);
    if (!auth.ok) return auth.denied;

    // BACKWARD COMPAT, one release: with NEITHER paging param the response is the
    // legacy bare array of the WHOLE feed — byte-for-byte what the DEPLOYED wallet
    // parses (it calls fetchHistory, which expects an array and would read
    // `{items,nextBefore}` as zero activity). Asking for either param opts into
    // the envelope. Remove the bare-array branch once no client in the wild
    // predates the release that ships fetchHistoryPage.
    const rawLimit = ctx.query.get("limit");
    const rawBefore = ctx.query.get("before");
    const paged = rawLimit !== null || rawBefore !== null;

    const limit = rawLimit === null ? DEFAULT_LIMIT : wholeNumber(rawLimit);
    if (limit === null || limit < 1 || limit > MAX_LIMIT) {
      return { status: 400, body: { error: `limit must be an integer in 1..${MAX_LIMIT}`, limit: rawLimit } };
    }
    const before = rawBefore === null ? undefined : wholeNumber(rawBefore);
    if (before === null) {
      return { status: 400, body: { error: "before must be an integer seq >= 0", before: rawBefore } };
    }

    if (!ctx.ix.ledger) {
      // Arbiter mode but ingest has not built the ledger yet (pre first ingest).
      return { status: 503, body: { error: "arbiter ledger not built yet" } };
    }
    // Wire shapes owned by @bongtu/core/indexerApi (server-adapter typing).
    if (!paged) {
      const legacy: HistoryItem[] = ctx.ix.ledger.historyOf(auth.pub[0], auth.pub[1]);
      return { status: 200, body: legacy, headers: AUTH_HEADER };
    }
    const items: HistoryItem[] = ctx.ix.ledger.historyOf(auth.pub[0], auth.pub[1], { limit, before });
    // A SHORT page means the feed ran out, so there is nothing left to ask for. A
    // full page may or may not have more behind it; the honest answer is a cursor,
    // and the caller learns the feed ended when that next page comes back short.
    const body: HistoryPage = {
      items,
      nextBefore: items.length === limit ? items[items.length - 1].seq : null,
    };
    return { status: 200, body, headers: AUTH_HEADER };
  },
};
