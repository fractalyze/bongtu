import type { Route } from "../router.js";

// SPEC §6b `/path/:leafIndex`. 404 out-of-range, 422 batch-interior leaf (siblings
// not chain-recoverable, §11-7). No root-agreement guard here: MirrorTree.path
// asserts the reconstructed root against the mirror internally (→ 500 via the
// router catch if it ever diverges, which the per-insert asserts make unreachable).
export const path: Route = {
  method: "GET",
  pattern: /^\/path\/(\d+)$/,
  handle({ ix, params }) {
    const leafIndex = Number(params[0]);
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
    return {
      status: 200,
      body: {
        leafIndex,
        siblings: p.siblings.map((x) => x.toString()),
        pathIndices: p.pathIndices,
        root: p.root.toString(),
      },
    };
  },
};
