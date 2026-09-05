import type { Route } from "../router.js";

import { currentAlarms } from "../../alarms.js";

// A tail stuck this many polls in a row is "wedged", not momentarily unlucky —
// one transient RPC hiccup (or a poll racing a fresh block) must not flip ok.
const PERSISTENT_FAILURE_STREAK = 3;

// SPEC §6b `/health` — an honest liveness signal, not a hard-coded ok:true.
// ok  = the mirror exists (initial ingest completed) AND the tail poll is not
//       persistently failing (a genuine mirror-root divergence, the system's
//       loudest invariant, lands here as a failure streak).
// The raw poll state (lastBlock / lastSuccessAt / lastError /
// consecutiveFailures) is included so a caller can see "wedged since when".
export const health: Route = {
  method: "GET",
  pattern: "/health",
  handle({ ix }) {
    const ok = !!ix.tree && ix.consecutiveFailures < PERSISTENT_FAILURE_STREAK;
    return {
      status: 200,
      body: {
        ok,
        lastBlock: ix.store.lastBlock,
        nextLeafIndex: ix.tree ? ix.tree.nextLeafIndex() : 0,
        batchSize: ix.batchSize,
        // Same population as GET /alarms BY CONSTRUCTION: the one aggregate
        // (src/alarms.ts currentAlarms), counted here instead of served.
        alarms: currentAlarms(ix, Math.floor(Date.now() / 1000)).length,
        lastSuccessAt: ix.lastSuccessAt,
        lastError: ix.lastError,
        lastErrorAt: ix.lastErrorAt,
        consecutiveFailures: ix.consecutiveFailures,
        // Replica head-races (retried, never part of the streak): a caller can
        // tell "noisy RPC but progressing" from "wedged" without the logs.
        transientHeadRaces: ix.transientHeadRaces,
        lastTransientAt: ix.lastTransientAt,
      },
    };
  },
};
