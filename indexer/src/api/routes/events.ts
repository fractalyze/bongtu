import type { Route } from "../router.js";

// SPEC §6b `/events`: the cursor-paged ciphertext feed. `disclosure` is projected
// down to its status string; the full DisclosureResult is served only on /alarms.
export const events: Route = {
  method: "GET",
  pattern: "/events",
  handle({ ix, query }) {
    const cursor = query.has("cursor") ? Number(query.get("cursor")) : -1;
    const limit = query.has("limit") ? Number(query.get("limit")) : 1000;
    if (!Number.isInteger(cursor) || cursor < -1) {
      return { status: 400, body: { error: "cursor must be an integer >= -1", cursor: query.get("cursor") } };
    }
    if (!Number.isInteger(limit) || limit < 1) {
      return { status: 400, body: { error: "limit must be an integer >= 1", limit: query.get("limit") } };
    }
    const out = ix.store.events(cursor, limit).map((e) => ({
      seq: e.seq,
      txHash: e.txHash,
      blockNumber: e.blockNumber,
      kind: e.kind,
      epoch: e.epoch,
      ecdhPublicKey: e.ecdhPublicKey,
      encryptionNonce: e.encryptionNonce,
      slices: e.slices,
      ciphertext: e.ciphertext,
      disclosure: e.disclosure ? e.disclosure.status : undefined,
    }));
    return { status: 200, body: out };
  },
};
