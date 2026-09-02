// The stealth-withdraw announcement feed:
//
//   GET /announcements?cursor=&limit=          PUBLIC (both modes) — every
//       announcement, cursor-paged by feed seq: the trustless scan-all path a
//       wallet that distrusts this indexer walks with its view key.
//   GET /announcements?owner=&ts=&sig=|token=  ARBITER MODE — only the caller's
//       own announcements, behind the same read-auth as /notes. Zero marginal
//       disclosure: the arbiter already learns each withdraw's owner from the
//       authority envelope, so serving the per-owner slice reveals nothing it
//       does not already hold — it just spares the wallet the O(all) scan.
//
// The route is ONLY param validation, mode fences, auth, and assembly — the
// house shape /notes and /history set. The two facts it serves live where they
// are owned: WHICH feed entries are announcements is the store's projection
// (StorePort.announcements — ingest attaches `.announcement` only for REAL
// stealth announcements, core isStealthAnnouncement, so no zero-check anywhere
// here), and WHICH withdraws are the caller's is the ledger's attribution
// (PostgresLedger.withdrawTxHashesOf — the same decrypted history rows
// historyOf serves).

import type { Route, RouteResult } from "../router.js";
import type { WithdrawAnnouncementRecord } from "@bongtu/core/indexerApi";
import { authorizeOwner, AUTH_HEADER } from "../readAuth.js";

const DEFAULT_LIMIT = 5000;

export const announcements: Route = {
  method: "GET",
  pattern: "/announcements",
  handle(ctx): RouteResult {
    const { ix, query } = ctx;

    const owner = query.get("owner");
    if (owner === null) {
      const cursor = Number(query.get("cursor") ?? -1);
      const limit = Number(query.get("limit") ?? DEFAULT_LIMIT);
      if (!Number.isInteger(cursor) || !Number.isInteger(limit) || limit <= 0) {
        return { status: 400, body: { error: "cursor/limit must be integers (limit > 0)" } };
      }
      return { status: 200, body: ix.store.announcements(cursor, limit) };
    }

    // Per-owner slice: arbiter-only, because only the decrypted ledger can say
    // which withdraws are the caller's. A public indexer structurally cannot
    // serve it (and must not pretend to).
    if (!ix.arbiterMode) {
      return { status: 404, body: { error: "owner-filtered announcements exist only in arbiter mode; use the public cursor feed" } };
    }
    const auth = authorizeOwner(ctx);
    if (!auth.ok) return auth.denied;
    if (!ix.ledger) {
      return { status: 503, body: { error: "arbiter ledger not built yet" } };
    }
    const mine = ix.ledger.withdrawTxHashesOf(auth.pub[0], auth.pub[1]);
    const body: WithdrawAnnouncementRecord[] = ix.store.announcements().filter((a) => mine.has(a.txHash));
    return { status: 200, body, headers: AUTH_HEADER };
  },
};
