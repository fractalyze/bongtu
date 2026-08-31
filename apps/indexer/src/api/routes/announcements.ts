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
// Announcements are withdraw-feed metadata, not their own table: the ingest
// attaches each WithdrawAnnouncement to its paired Withdrawn feed entry, and
// the owner attribution is the ledger's history (kind=withdraw rows carry the
// tx hashes the owner's envelopes decrypted from).

import type { Route, RouteResult } from "../router.js";
import type { WithdrawAnnouncementRecord } from "@bongtu/core/indexerApi";
import { authorizeOwner, AUTH_HEADER } from "../readAuth.js";

const DEFAULT_LIMIT = 5000;

export const announcements: Route = {
  method: "GET",
  pattern: "/announcements",
  handle(ctx): RouteResult {
    const { ix, query } = ctx;
    const all: WithdrawAnnouncementRecord[] = [];
    for (const e of ix.store.allEvents()) {
      if (e.kind !== "withdraw" || !e.announcement) continue;
      all.push({
        seq: e.seq,
        txHash: e.txHash,
        blockNumber: e.blockNumber,
        recipient: e.announcement.recipient,
        ephemeralPub: e.announcement.ephemeralPub,
        viewTag: e.announcement.viewTag,
      });
    }

    const owner = query.get("owner");
    if (owner === null) {
      const cursor = Number(query.get("cursor") ?? -1);
      const limit = Number(query.get("limit") ?? DEFAULT_LIMIT);
      if (!Number.isInteger(cursor) || !Number.isInteger(limit) || limit <= 0) {
        return { status: 400, body: { error: "cursor/limit must be integers (limit > 0)" } };
      }
      return { status: 200, body: all.filter((a) => a.seq > cursor).slice(0, limit) };
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
    const mine = new Set(
      ix.ledger
        .historyOf(auth.pub[0], auth.pub[1])
        .filter((h) => h.kind === "withdraw")
        .map((h) => h.txHash),
    );
    return { status: 200, body: all.filter((a) => mine.has(a.txHash)), headers: AUTH_HEADER };
  },
};
