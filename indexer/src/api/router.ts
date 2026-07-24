// HTTP read API (SPEC §6b) — router + JSON envelope. Minimal node:http, no framework.
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
//   GET /nullifiers          -> string[]  (spent nullifier set; PUBLIC, key-free)
//   GET /notes?owner=x,y     -> [{ value, salt, leafIndex, commitment, txHash,
//                               spent }]  (ARBITER MODE ONLY — registered only when
//                               the indexer holds the arbiter key; else 404)
//
// All endpoints serve INGESTED state (the MirrorTree is asserted against the
// contract per insert and at every scanned head), so the API stays mutually
// consistent and available even when the RPC is not. In arbiter mode /path also
// serves within-batch leaves (the ledger filled them); public mode 422s those.
//
// Dispatch is a plain ordered `routes` table matched by (method, pattern), NOT an
// if/else ladder: each route's `handle` is a PURE function of the indexer + parsed
// params/query returning { status, body }, and the router owns the one JSON
// envelope, the no-match 404, and the catch-all 500. No node:http type ever
// reaches a route handler.
//
// The core indexer is NOT auditor-mode: it serves only public chain data
// (ciphertext, roots, paths) and never holds or returns any user private key —
// trial-decrypt is the wallet's job (SPEC §7 client-side-decrypt model).

import { createServer, type ServerResponse } from "node:http";
import type { Indexer } from "../ingest.js";
import { head } from "./routes/head.js";
import { events } from "./routes/events.js";
import { path } from "./routes/path.js";
import { alarms } from "./routes/alarms.js";
import { health } from "./routes/health.js";
import { nullifiers } from "./routes/nullifiers.js";
import { notes } from "./routes/notes.js";

/** What a route handler receives: the indexer + the parsed request, no HTTP types. */
export interface RouteContext {
  ix: Indexer;
  params: string[]; // regex capture groups (e.g. the /path/:leafIndex digits)
  query: URLSearchParams;
}
/** What a route handler returns: an HTTP status + a JSON-serialisable body. */
export interface RouteResult {
  status: number;
  body: unknown;
  headers?: Record<string, string>; // merged over the JSON content-type (e.g. /notes deferred-auth notice)
}
/** One endpoint: matched by (method, pattern), served by a pure `handle`. */
export interface Route {
  method: string;
  pattern: string | RegExp; // exact pathname (string) or a capture regex
  handle(ctx: RouteContext): RouteResult;
}

// Ordered match table. The patterns are disjoint, so order is not correctness-
// critical; it reads top-down like the SPEC §6b endpoint list above. `/nullifiers`
// is public (always on); `/notes` is ARBITER-ONLY and composed in per-indexer by
// makeHandler, so public mode returns 404 for it (the endpoint does not exist).
export const routes: Route[] = [head, events, path, alarms, health, nullifiers];

function writeJson(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  const s = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json", ...(headers ?? {}) });
  res.end(s);
}

/** Build (but do not start) the request handler for an Indexer. The route set is
 *  fixed at build time: arbiter mode adds /notes, so an unauthorised indexer can
 *  never serve a user's decrypted notes even by request-path (the route is absent). */
export function makeHandler(ix: Indexer) {
  const activeRoutes = ix.arbiterMode ? [...routes, notes] : routes;
  return (req: { url?: string; method?: string }, res: ServerResponse): void => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const pathname = url.pathname;
      for (const route of activeRoutes) {
        if (route.method !== req.method) continue;
        let params: string[] | null = null;
        if (typeof route.pattern === "string") {
          if (route.pattern === pathname) params = [];
        } else {
          const m = route.pattern.exec(pathname);
          if (m) params = m.slice(1);
        }
        if (params === null) continue;
        const { status, body, headers } = route.handle({ ix, params, query: url.searchParams });
        return writeJson(res, status, body, headers);
      }
      return writeJson(res, 404, { error: "not found", path: pathname });
    } catch (e) {
      return writeJson(res, 500, { error: (e as Error).message });
    }
  };
}

/** Start the API server on `port`; resolves with a stop() closer. */
export function startApi(ix: Indexer, port: number): Promise<{ port: number; stop: () => Promise<void> }> {
  const handler = makeHandler(ix);
  const server = createServer((req, res) => handler(req, res));
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
