import type { Route } from "../router.js";
import type { Alarm } from "@bongtu/core/indexerApi";

import { currentAlarms } from "../../alarms.js";

/**
 * GET /alarms serves the aggregate owned by src/alarms.ts (currentAlarms) —
 * what counts as an alarm, which sources feed it, and the wire typing against
 * @bongtu/core/indexerApi all live THERE; /health counts the same call. */
export type { Alarm } from "@bongtu/core/indexerApi";

export const alarms: Route = {
  method: "GET",
  pattern: "/alarms",
  handle({ ix }) {
    // The served-blob registry (SOLR §3.3.2) joins the SAME "disclosure"
    // class: a late-loaded blob's mismatch, or a batch unserved past grace
    // ("withheld"). Empty on the EVM backend, so the feed is byte-identical
    // there.
    // ONE aggregate (src/alarms.ts currentAlarms) builds the three-source
    // union; /health counts the same call, so list and count cannot disagree.
    const body: Alarm[] = currentAlarms(ix, Math.floor(Date.now() / 1000));
    return { status: 200, body };
  },
};
