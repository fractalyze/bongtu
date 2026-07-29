import type { Route } from "../router.js";
import type { PathResult } from "@bongtu/core/indexerApi";
import { authorizeOwner, AUTH_HEADER } from "../readAuth.js";

// SPEC §6b `/path/:leafIndex` (wire shape owned by @bongtu/core/indexerApi).
// 404 out-of-range, 422 batch-interior leaf (siblings
// not chain-recoverable, §11-7). No root-agreement guard here: MirrorTree.path
// asserts the reconstructed root against the mirror internally (→ 500 via the
// router catch if it ever diverges, which the per-insert asserts make unreachable).
//
// A REAL path INTO a disburse batch exists only in arbiter mode (the ledger
// filled the block from the decrypted authority envelope). Its low levels are
// OTHER recipients' commitments — exactly the data public mode calls
// not-chain-recoverable — so that read is gated: the caller must pass the same
// read-auth /notes uses (api/readAuth.ts, signed query or view token) AND the
// authenticated owner must hold the queried leaf in the arbiter ledger (403
// otherwise — a recipient may open its own slot, never a neighbour's).
// Single-append leaves stay auth-free in both modes: their siblings are
// recomputable from public chain data by anyone running a public indexer, so a
// gate there would protect nothing.
export const path: Route = {
  method: "GET",
  pattern: /^\/path\/(\d+)$/,
  handle(ctx) {
    const { ix } = ctx;
    const leafIndex = Number(ctx.params[0]);
    const nli = ix.tree ? ix.tree.nextLeafIndex() : 0;
    if (!ix.tree || leafIndex < 0 || leafIndex >= nli) {
      return { status: 404, body: { error: "leafIndex out of range", leafIndex } };
    }
    const p = ix.tree.path(leafIndex);
    if ("batchLeaf" in p) {
      return {
        status: 422,
        body: {
          error: "no path: leaf is inside a disburse batch (siblings not chain-recoverable)",
          reason: "batch-leaf",
          leafIndex,
        },
      };
    }
    const gated = ix.tree.isBatch(Math.floor(leafIndex / ix.tree.B));
    if (gated) {
      const auth = authorizeOwner(ctx);
      if (!auth.ok) return auth.denied;
      if (!ix.ledger) {
        // Unreachable in practice (only the ledger fills a batch), kept as a
        // fail-closed guard against a future fill path that bypasses it.
        return { status: 503, body: { error: "arbiter ledger not built yet" } };
      }
      const owned = ix.ledger.notesOf(auth.pub[0], auth.pub[1]).some((n) => n.leafIndex === leafIndex);
      if (!owned) {
        return { status: 403, body: { error: "authenticated owner does not hold this leaf", leafIndex } };
      }
    }
    const body: PathResult = {
      leafIndex,
      siblings: p.siblings.map((x) => x.toString()),
      pathIndices: p.pathIndices,
      root: p.root.toString(),
    };
    return { status: 200, body, headers: gated ? AUTH_HEADER : undefined };
  },
};
