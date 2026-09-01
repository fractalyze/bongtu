// HTTP surface — minimal node:http, no framework, same wire discipline as the
// indexer's api/router.ts: the handlers (relay.ts) are pure functions returning
// { status, body }, this file owns the JSON envelope, the body-size cap, the
// no-match 404 and the catch-all 500. Two endpoints only:
//
//   POST /relay   -> { txHash }            (400 / 422 / 502 on failure)
//   GET  /health  -> { ok, submitter, balanceWei }

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { handleHealth, handleRelay, type RelayerChain, type RelayResult } from "./relay.js";

function writeJson(res: ServerResponse, { status, body }: RelayResult): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body, null, 2));
}

// A relay body is a proof (8 field elements), 27 public signals and a 1088-byte
// KEM ct — comfortably under 64 KiB; the cap stops a runaway body, not a real one.
const MAX_BODY_BYTES = 64 * 1024;

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(chunk as Buffer);
    const size = chunks.reduce((n, c) => n + c.length, 0);
    if (size > MAX_BODY_BYTES) throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (text === "") return undefined;
  return JSON.parse(text); // malformed JSON -> throw (mapped to 400 below)
}

/** Build (but do not start) the request handler — exported so tests can drive it
 *  over fakes without binding a port. */
export function makeHandler(chain: RelayerChain) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "GET" && url.pathname === "/health") {
        return writeJson(res, await handleHealth(chain));
      }
      if (req.method === "POST" && url.pathname === "/relay") {
        const bodyRead: { body?: unknown; err?: Error } = await (async () => {
          try {
            return { body: await readJsonBody(req) };
          } catch (e) {
            return { err: e as Error };
          }
        })();
        if (bodyRead.err) {
          return writeJson(res, { status: 400, body: { error: `bad request body: ${bodyRead.err.message}` } });
        }
        return writeJson(res, await handleRelay(chain, bodyRead.body));
      }
      return writeJson(res, { status: 404, body: { error: "not found", path: url.pathname } });
    } catch (e) {
      return writeJson(res, { status: 500, body: { error: (e as Error).message } });
    }
  };
}

/** Start the API server on `port`; resolves with the bound port and a stop() closer. */
export function startApi(
  chain: RelayerChain,
  port: number,
): Promise<{ port: number; stop: () => Promise<void> }> {
  const handler = makeHandler(chain);
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
