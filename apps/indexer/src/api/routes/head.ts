import type { Route } from "../router.js";

// SPEC §6b `/head`.
export const head: Route = {
  method: "GET",
  pattern: "/head",
  handle({ ix }) {
    if (!ix.tree) return { status: 503, body: { error: "not ingested yet" } };
    return {
      status: 200,
      body: { root: ix.tree.root().toString(), nextLeafIndex: ix.tree.nextLeafIndex() },
    };
  },
};
