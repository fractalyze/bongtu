// HTTP read API (SPEC §6b). Minimal node:http — no framework dependency.
//
//   GET /head                -> { root, nextLeafIndex }   (ingested mirror state)
//   GET /events?cursor=&limit= -> [{ txHash, blockNumber, ecdhPublicKey,
//                                    encryptionNonce, epoch, slices:[{offset,elts,
//                                    leafIndex}], kind, ciphertext[], disclosure? }]
//   GET /path/:leafIndex     -> { leafIndex, siblings[], pathIndices[], root }
//   GET /alarms              -> [DisclosureResult]  (every non-passing disclosure:
//                               mismatch = proven tamper, unverifiable/withheld =
//                               publication gap for the auditor to judge)
//   GET /health              -> { ok, lastBlock, nextLeafIndex, batchSize }
//
// All endpoints serve INGESTED state (the mirror is asserted against the
// contract per insert and at every scanned head), so the API stays mutually
// consistent and available even when the RPC is not.
//
// The core indexer is NOT auditor-mode: it serves only public chain data
// (ciphertext, roots, paths) and never holds or returns any user private key —
// trial-decrypt is the wallet's job (SPEC §7 client-side-decrypt model).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Indexer } from "./ingest.js";
import { buildPath } from "./paths.js";

function json(res: ServerResponse, code: number, body: unknown): void {
  const s = JSON.stringify(body, null, 2);
  res.writeHead(code, { "content-type": "application/json" });
  res.end(s);
}

/** Build (but do not start) the request handler for an Indexer. */
export function makeHandler(ix: Indexer) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const path = url.pathname;

      if (path === "/head") {
        if (!ix.mirror) return json(res, 503, { error: "not ingested yet" });
        return json(res, 200, {
          root: ix.mirror.getRoot().toString(),
          nextLeafIndex: ix.mirror.getNextLeafIndex(),
        });
      }

      if (path === "/health") {
        return json(res, 200, {
          ok: true,
          lastBlock: ix.store.lastBlock,
          nextLeafIndex: ix.mirror ? ix.mirror.getNextLeafIndex() : 0,
          batchSize: ix.batchSize,
          alarms: ix.store.getAlarms().length,
        });
      }

      if (path === "/events") {
        const cursor = url.searchParams.has("cursor") ? Number(url.searchParams.get("cursor")) : -1;
        const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 1000;
        if (!Number.isInteger(cursor) || cursor < -1) {
          return json(res, 400, { error: "cursor must be an integer >= -1", cursor: url.searchParams.get("cursor") });
        }
        if (!Number.isInteger(limit) || limit < 1) {
          return json(res, 400, { error: "limit must be an integer >= 1", limit: url.searchParams.get("limit") });
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
        return json(res, 200, out);
      }

      if (path === "/alarms") {
        return json(res, 200, ix.store.getAlarms());
      }

      const m = path.match(/^\/path\/(\d+)$/);
      if (m) {
        const leafIndex = Number(m[1]);
        const nli = ix.mirror ? ix.mirror.getNextLeafIndex() : 0;
        if (!ix.mirror || leafIndex < 0 || leafIndex >= nli) {
          return json(res, 404, { error: "leafIndex out of range", leafIndex });
        }
        const p = buildPath(ix.store, leafIndex, nli, ix.mirror.H, ix.batchSize);
        if ("batchLeaf" in p) {
          return json(res, 422, {
            error: "no path: leaf is inside a disburse batch (siblings not chain-recoverable)",
            reason: "batch-leaf",
            leafIndex,
          });
        }
        if (p.root !== ix.mirror.getRoot()) {
          // Never serve a non-folding path: the builder reconstructs the root
          // independently from store leaf records, and any divergence from the
          // per-insert-asserted mirror means those records are corrupt.
          return json(res, 500, { error: "internal: path root diverged from mirror", leafIndex });
        }
        return json(res, 200, {
          leafIndex,
          siblings: p.siblings.map((x) => x.toString()),
          pathIndices: p.pathIndices,
          root: p.root.toString(),
        });
      }

      return json(res, 404, { error: "not found", path });
    } catch (e) {
      return json(res, 500, { error: (e as Error).message });
    }
  };
}

/** Start the API server on `port`; resolves with a stop() closer. */
export function startApi(ix: Indexer, port: number): Promise<{ port: number; stop: () => Promise<void> }> {
  const handler = makeHandler(ix);
  const server = createServer((req, res) => void handler(req, res));
  return new Promise((resolve) => {
    server.listen(port, () => {
      const addr = server.address();
      const actual = typeof addr === "object" && addr ? addr.port : port;
      resolve({
        port: actual,
        stop: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}
