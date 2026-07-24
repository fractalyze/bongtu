// Local prover-cli HTTP helper (SPEC §6 "we prove in the demo"). Runs on the
// employer's GPU box, NOT in the browser: the 1.24GB disburse zkey + rabbitsnark
// binary can't ship to a page. The browser assembles a ProvingRequest, POSTs it
// here, and gets back Groth16 calldata to submit via MetaMask.
//
//   POST /prove   body = a ProvingRequest JSON (from employer-mode "Build")
//                 -> 200 { a, b, c, pub }   (prover-cli calldata)
//
// Run (from apps/admin, on the GPU box):
//   PORT=8700 node --import tsx prover-helper.ts
// The GPU env is the same prover-cli/CLAUDE.md contract: CUDA_VISIBLE_DEVICES=0,
// BONGTU_NODE_MODULES set, the 1.24GB artifacts/circuit.zkey present. Cold zkey
// compile is ~2min; warm ~0.5s.

import { createServer } from "node:http";
import { prove } from "../../prover-cli/src/prove.js";
import type { ProvingRequest } from "../../prover-cli/src/types.js";

const PORT = Number(process.env.PORT || 8700);
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

const server = createServer((req, res) => {
  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    res.end();
    return;
  }
  if (req.method !== "POST" || !req.url?.startsWith("/prove")) {
    res.writeHead(404, { "content-type": "application/json", ...CORS });
    res.end(JSON.stringify({ error: "POST /prove only" }));
    return;
  }
  const chunks: Buffer[] = [];
  req.on("data", (c) => chunks.push(c as Buffer));
  req.on("end", () => {
    void (async () => {
      try {
        const request = JSON.parse(Buffer.concat(chunks).toString("utf8")) as ProvingRequest;
        console.log(`prove: circuit=${request.circuit} backend=${request.backend ?? "default"}`);
        const calldata = await prove(request);
        res.writeHead(200, { "content-type": "application/json", ...CORS });
        res.end(JSON.stringify(calldata));
      } catch (e) {
        const msg = e instanceof Error ? (e.stack ?? e.message) : String(e);
        console.error("prove error:", msg);
        res.writeHead(500, { "content-type": "application/json", ...CORS });
        res.end(JSON.stringify({ error: msg }));
      }
    })();
  });
});

server.listen(PORT, () => console.log(`bongtu prover-helper on :${PORT} (POST /prove)`));
