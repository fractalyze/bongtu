import type { Route } from "../router.js";
import type { Head } from "@bongtu/core/indexerApi";

// SPEC §6b `/head` (wire shape owned by @bongtu/core/indexerApi).
export const head: Route = {
  method: "GET",
  pattern: "/head",
  handle({ ix }) {
    if (!ix.tree) return { status: 503, body: { error: "not ingested yet" } };
    const body: Head = { root: ix.tree.root().toString(), nextLeafIndex: ix.tree.nextLeafIndex() };
    return { status: 200, body };
  },
};
