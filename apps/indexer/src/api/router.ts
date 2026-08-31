// HTTP read API (SPEC §6b) — router + JSON envelope. Minimal node:http, no framework.
//
//   GET /head                -> { root, nextLeafIndex }   (ingested mirror state)
//   GET /events?cursor=&limit= -> [{ txHash, blockNumber, ecdhPublicKey,
//                                    encryptionNonce, epoch, slices:[{offset,elts,
//                                    leafIndex}], kind, ciphertext[], disclosure? }]
//   GET /path/:leafIndex     -> { leafIndex, siblings[], pathIndices[], root }
//                               (batch-interior leaf: /notes read-auth + leaf
//                                ownership required — routes/path.ts)
//   GET /alarms              -> [Alarm]  (single discriminated feed: every
//                               non-passing disclosure as { type: "disclosure" },
//                               plus — arbiter mode only — every envelope
//                               cross-check failure as { type: "envelope" })
//   GET /health              -> { ok (tree exists AND tail not persistently
//                                failing), lastBlock, nextLeafIndex, batchSize,
//                                alarms (disclosure+envelope count), lastSuccessAt,
//                                lastError, lastErrorAt, consecutiveFailures }
//   GET /nullifiers          -> string[]  (spent nullifier set; PUBLIC, key-free)
//   GET /announcements       -> [WithdrawAnnouncementRecord]  (PUBLIC cursor
//                               feed; with ?owner= — ARBITER MODE, /notes
//                               read-auth — only the caller's own)
//   GET  /names/:name        -> NameRecord  (PUBLIC name directory: owner bjj
//                               pubkey + stealth meta-address; names.ts)
//   POST /names {name,owner,viewPub,spendPub,ts,sig} -> NameRecord  (PUBLIC;
//                               owner-signed, payload-bound — routes/names.ts)
//   GET /notes?owner=x,y     -> [{ value, salt, leafIndex, commitment, txHash,
//                               spent }]  (ARBITER MODE ONLY — registered only when
//                               the indexer holds the arbiter key; else 404)
//   GET /history?owner=&ts=&sig=[&limit=&before=] -> [{ kind, counterparty,
//                               amount, txHash, blockTimestamp, seq }] (ARBITER
//                               MODE ONLY; same bjj read-auth as /notes;
//                               newest-first). With `limit` or `before` the body
//                               is ONE page as { items, nextBefore }; with
//                               neither it stays the legacy whole-feed array.
//   GET /auth/challenge?owner= -> { challenge, expiresAt, hostBindings }
//                                                           (ARBITER MODE ONLY)
//   POST /auth {owner,challenge,sig} -> { token, exp }       (ARBITER MODE ONLY;
//                               the token then authorises /notes + /history via
//                               ?token= instead of ts/sig — see api/viewtoken.ts)
//
// All endpoints serve INGESTED state (the MirrorTree is asserted against the
// contract per insert and at every scanned head), so the API stays mutually
// consistent and available even when the RPC is not. In arbiter mode /path also
// serves within-batch leaves (the ledger filled them) — but only to the leaf's
// authenticated owner; public mode 422s those.
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

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Indexer } from "../ingest.js";
import { head } from "./routes/head.js";
import { events } from "./routes/events.js";
import { path } from "./routes/path.js";
import { alarms } from "./routes/alarms.js";
import { health } from "./routes/health.js";
import { nullifiers } from "./routes/nullifiers.js";
import { nameRegister, nameResolve } from "./routes/names.js";
import { announcements } from "./routes/announcements.js";
import { notes } from "./routes/notes.js";
import { history } from "./routes/history.js";
import { authChallenge, authRedeem } from "./routes/auth.js";
import { resolvePublicUrls, resolveTokenSecret, ViewTokenService } from "./viewtoken.js";

/** What a route handler receives: the indexer + the parsed request, no HTTP types. */
export interface RouteContext {
  ix: Indexer;
  /** view-token issue/verify (api/viewtoken.ts) — one service per server, and
   *  null in public mode, which has no token-authed route to serve. */
  tokens: ViewTokenService | null;
  params: string[]; // regex capture groups (e.g. the /path/:leafIndex digits)
  query: URLSearchParams;
  /** parsed JSON request body (POST routes only; undefined when absent/empty). */
  body?: unknown;
}
/** What a route handler returns: an HTTP status + a JSON-serialisable body. */
export interface RouteResult {
  status: number;
  body: unknown;
  headers?: Record<string, string>; // merged over the JSON content-type (e.g. /notes enforced-auth notice)
}
/** One endpoint: matched by (method, pattern), served by a pure `handle`. */
export interface Route {
  method: string;
  pattern: string | RegExp; // exact pathname (string) or a capture regex
  handle(ctx: RouteContext): RouteResult | Promise<RouteResult>;
}

// Ordered match table. The patterns are disjoint, so order is not correctness-
// critical; it reads top-down like the SPEC §6b endpoint list above. `/nullifiers`
// is public (always on); `/notes` + `/history` are ARBITER-ONLY and composed in
// per-indexer by makeHandler, so public mode returns 404 for them (the endpoints
// do not exist).
export const routes: Route[] = [head, events, path, alarms, health, nullifiers, nameResolve, nameRegister, announcements];

function writeJson(res: ServerResponse, status: number, body: unknown, headers?: Record<string, string>): void {
  const s = JSON.stringify(body, null, 2);
  res.writeHead(status, { "content-type": "application/json", ...(headers ?? {}) });
  res.end(s);
}

// POST bodies are small JSON structs (/auth is 3 short strings); cap well above
// that so a runaway body cannot balloon memory.
const MAX_BODY_BYTES = 64 * 1024;

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    chunks.push(chunk as Buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (text === "") return undefined;
  return JSON.parse(text); // malformed JSON -> throw (mapped to 400 below)
}

/** Build (but do not start) the request handler for an Indexer. The route set is
 *  fixed at build time: arbiter mode adds /notes + /history + the /auth token
 *  endpoints, so an unauthorised indexer can never serve a user's decrypted notes
 *  even by request-path (the routes are absent). `tokens` is REQUIRED (null in
 *  public mode, which has no route that takes a token): the service must be built
 *  by whoever knows the origins it binds to — startApi, once the port is bound —
 *  so there is exactly ONE assembly point and no path that can mint tokens for an
 *  origin clients never dial. */
export function makeHandler(ix: Indexer, tokens: ViewTokenService | null) {
  const activeRoutes = ix.arbiterMode ? [...routes, notes, history, authChallenge, authRedeem] : routes;
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
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
        // Only a matched POST route pays the body read; a malformed body is the
        // CALLER's error (400), never the catch-all 500.
        let body: unknown;
        if (req.method === "POST") {
          try {
            body = await readJsonBody(req);
          } catch (e) {
            return writeJson(res, 400, { error: `bad request body: ${(e as Error).message}` });
          }
        }
        const { status, body: resBody, headers } = await route.handle({ ix, tokens, params, query: url.searchParams, body });
        return writeJson(res, status, resBody, headers);
      }
      return writeJson(res, 404, { error: "not found", path: pathname });
    } catch (e) {
      return writeJson(res, 500, { error: (e as Error).message });
    }
  };
}

/** Start the API server on `port`; resolves with the bound port, the view-token
 *  origins it will accept, and a stop() closer. The handler is built INSIDE the
 *  listen callback because the PUBLIC_URL fallback needs the actually-bound port
 *  (callers pass 0 for an ephemeral one); no request can arrive before then. */
export function startApi(
  ix: Indexer,
  port: number,
): Promise<{ port: number; publicUrls: string[]; stop: () => Promise<void> }> {
  let handler: ReturnType<typeof makeHandler> | null = null;
  const server = createServer((req, res) => void handler?.(req, res));
  return new Promise((resolve) => {
    server.listen(port, () => {
      const addr = server.address();
      const actual = typeof addr === "object" && addr ? addr.port : port;
      const publicUrls = resolvePublicUrls(process.env, actual);
      handler = makeHandler(
        ix,
        ix.arbiterMode ? new ViewTokenService(resolveTokenSecret(), { publicUrls }) : null,
      );
      resolve({
        port: actual,
        publicUrls,
        stop: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}
