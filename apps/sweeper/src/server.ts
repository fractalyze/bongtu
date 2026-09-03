// HTTP surface — minimal node:http, no framework, the relayer server.ts wire
// discipline verbatim: the handler (sweep.ts handleHealth) is a pure function
// returning { status, body }, this file owns the JSON envelope, the no-match
// 404 and the catch-all 500. ONE endpoint only — the sweeper takes no requests
// (its work source is the poll loop), it only answers "am I alive and funded":
//
//   GET /health -> { ok, sweeper, balanceWei, lastSweepAt, unswept }

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { handleHealth, type SweeperChain, type SweeperState, type SweepResult } from "./sweep.js";

function writeJson(res: ServerResponse, { status, body }: SweepResult): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body, null, 2));
}

/** Build (but do not start) the request handler — exported so tests can drive it
 *  over fakes without binding a port. */
export function makeHandler(chain: SweeperChain, state: SweeperState) {
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "GET" && url.pathname === "/health") {
        return writeJson(res, await handleHealth(chain, state));
      }
      return writeJson(res, { status: 404, body: { error: "not found", path: url.pathname } });
    } catch (e) {
      return writeJson(res, { status: 500, body: { error: (e as Error).message } });
    }
  };
}

/** Start the API server on `port`; resolves with the bound port and a stop() closer. */
export function startApi(
  chain: SweeperChain,
  state: SweeperState,
  port: number,
): Promise<{ port: number; stop: () => Promise<void> }> {
  const handler = makeHandler(chain, state);
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
