import type { Route } from "../router.js";
import type { FeedEvent } from "@bongtu/core/indexerApi";

// SPEC §6b `/events`: the cursor-paged ciphertext feed. `disclosure` is projected
// down to its status string; the full DisclosureResult is served only on /alarms.
// The wire shape is owned by @bongtu/core/indexerApi — typing `out` against it is
// the server-adapter half of that contract. Consumer entries additionally carry
// viewTags / kemCiphertexts / batchId / outputCommitments (OPMOD §3.6 discovery
// material), and a consumer disburse gets its kem chunk-transport state joined
// in at serve time — chunk completion arrives in LATER blocks than the batch
// entry, so it lives in the KemChunkStore, never inside the immutable entry.
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
    const now = Math.floor(Date.now() / 1000);
    // The kem-pending → kem-withheld grace window (OPMOD §5): parsed ONCE at
    // boot through the config seam (chain.ts KEM_GRACE_SECONDS → ix.kemGraceSeconds,
    // garbage refuses to boot) — never a per-request process.env read. Tests
    // flip ix.kemGraceSeconds directly (the injectable seam).
    const grace = ix.kemGraceSeconds;
    const out: FeedEvent[] = ix.store.events(cursor, limit).map((e) => ({
      seq: e.seq,
      txHash: e.txHash,
      blockNumber: e.blockNumber,
      kind: e.kind,
      epoch: e.epoch,
      ecdhPublicKey: e.ecdhPublicKey,
      encryptionNonce: e.encryptionNonce,
      slices: e.slices,
      ciphertext: e.ciphertext,
      // A Solana disburse projects the served-blob registry's CURRENT verdict
      // first: the baked entry verdict describes the bytes held at ingest,
      // the registry's describes the bytes held NOW — after a post-ingest
      // blob swap only the latter is truthful. Registry silent (no blob, or
      // unserved within grace) => fall back to the baked verdict. EVM disburse
      // entries always bake a verdict and record nothing in the registry, so
      // only the fallback fires there.
      disclosure:
        e.kind === "disburse" && e.batchId !== undefined
          ? ix.disclosures.statusOf(e.batchId, now) ?? e.disclosure?.status
          : e.disclosure?.status,
      announcement: e.announcement,
      viewTags: e.viewTags,
      kemCiphertexts: e.kemCiphertexts,
      batchId: e.batchId,
      outputCommitments: e.outputCommitments,
      kem:
        e.kind === "disbursePriv" && e.batchId !== undefined
          ? ix.kem.projection(e.batchId, now, grace) ?? undefined
          : undefined,
    }));
    return { status: 200, body: out };
  },
};
