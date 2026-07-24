// prover-cli entry: read a ProvingRequest JSON, write the Groth16 calldata JSON.
//
// A thin wrapper over prove() — no CSV, no address resolution, no tx (SPEC §6).
// The request must already be a complete circom witness input (see types.ts);
// field elements are decimal strings (JSON has no bigint).
//
//   Usage:
//     prover-cli <request.json> [out.json]     # file in, file (or stdout) out
//     prover-cli - [out.json]                  # request on stdin
//     cat request.json | prover-cli            # request on stdin, calldata on stdout
//
// Exit 0 on success; non-zero (with the error on stderr) on any failure.

import { readFileSync, writeFileSync } from "node:fs";

import { prove } from "./prove.js";
import type { ProvingRequest } from "./types.js";

function readRequest(pathArg: string | undefined): ProvingRequest {
  // No path, or "-", means read the whole request from stdin (fd 0).
  const raw = !pathArg || pathArg === "-" ? readFileSync(0, "utf8") : readFileSync(pathArg, "utf8");
  const req = JSON.parse(raw) as ProvingRequest;
  if (!req || typeof req !== "object" || !("circuit" in req) || !("input" in req)) {
    throw new Error("prover-cli: request must be a JSON object with `circuit` and `input`");
  }
  return req;
}

async function main(): Promise<void> {
  const [inPath, outPath] = process.argv.slice(2);
  const req = readRequest(inPath);
  const calldata = await prove(req);
  const json = JSON.stringify(calldata, null, 2);
  if (outPath) {
    writeFileSync(outPath, json + "\n");
    console.error(`prover-cli: wrote ${req.circuit} calldata (${calldata.pub.length} publics) to ${outPath}`);
    return;
  }
  // stdout path: wait for the write to flush before exiting (a piped stdout write is
  // async, and process.exit() would truncate it otherwise).
  await new Promise<void>((resolve) => process.stdout.write(json + "\n", () => resolve()));
}

// snarkjs (ffjavascript) leaves worker threads open, so the event loop never drains
// on its own — the deploy scripts exit explicitly for the same reason. Exit 0 once
// the calldata is flushed so the CLI terminates instead of hanging.
main().then(
  () => process.exit(0),
  (e) => {
    console.error("prover-cli ERROR:", e && e.stack ? e.stack : e);
    process.exit(1);
  },
);
