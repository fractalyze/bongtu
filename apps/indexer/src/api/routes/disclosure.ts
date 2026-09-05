import type { Route } from "../router.js";

// SOLR §3.3.2 `GET /disclosure/{start_leaf_index}`: serve the institution-held
// disclosure blob for one disburse batch so ANY party can refold it (the one
// disclosureChain implementation) against the chain-committed
// DisburseBatch.disclosureHash — verification needs no key and no trust, only
// availability. Served in BOTH modes from the neutral registry: an EVM-backend
// indexer holds no batches (its disburse bytes are consensus-published), so
// the route 404s identically there, keeping the API surface one shape across
// backends. Elements are 32-byte 0x-hex in fold order (canonical wire — the
// verifier rejects >= r aliases before folding, byte equality not mod-p).
//
// The body always carries the registry's current `verdict` and the
// chain-committed `disclosureHash`, and a held blob with a non-passing
// verdict is served 409, not 200 — an honest client that skips its own
// refold must never mistake known-tampered bytes for clean ones.
export const disclosure: Route = {
  method: "GET",
  pattern: /^\/disclosure\/(\d+)$/,
  handle({ ix, params }) {
    const startLeafIndex = Number(params[0]);
    const now = Math.floor(Date.now() / 1000);
    const anchor = ix.disclosures.anchorOf(startLeafIndex);
    const verdict = ix.disclosures.statusOf(startLeafIndex, now);
    const disclosureHash =
      anchor === undefined ? undefined : "0x" + anchor.disclosureHash.toString(16).padStart(64, "0");
    const elements = ix.disclosures.blobOf(startLeafIndex);
    if (elements === null) {
      // Known batch, nothing held: still echo the anchor so the client knows
      // what the missing bytes were committed to.
      return { status: 404, body: { error: "no disclosure blob held for this batch", startLeafIndex, disclosureHash, verdict } };
    }
    return {
      status: verdict === "verified" ? 200 : 409,
      body: { startLeafIndex, elements, disclosureHash, verdict },
    };
  },
};
