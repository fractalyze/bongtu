import type { Route } from "../router.js";

// SPEC §6b `/health`.
export const health: Route = {
  method: "GET",
  pattern: "/health",
  handle({ ix }) {
    return {
      status: 200,
      body: {
        ok: true,
        lastBlock: ix.store.lastBlock,
        nextLeafIndex: ix.tree ? ix.tree.nextLeafIndex() : 0,
        batchSize: ix.batchSize,
        alarms: ix.store.getAlarms().length,
      },
    };
  },
};
