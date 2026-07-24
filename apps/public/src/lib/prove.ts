// Browser Groth16 proving for the two small CPU circuits (SPEC §6 transfer proving).
//
// GPL DECISION (SPEC §6, explicit): shipping snarkjs to the page IS distribution, so
// the Node-subprocess isolation the prover-cli uses does not apply here. The PoC
// takes option (a): accept GPL-3.0 for the public app, documented in README. snarkjs
// is dynamically imported so it only loads when the user actually proves.
//
// ASSET BOUNDARY (documented, SPEC §6 "one-time zkey download"): the wasm + zkey for
// transfer/withdraw are served as static assets at `${circuitBaseUrl}/<circuit>.wasm`
// and `.zkey`. They are NOT bundled (transfer.zkey ~28 MB, withdraw.zkey ~24 MB) —
// the deployer copies circuits/out/{transfer_js/transfer.wasm,transfer.zkey, ...}
// under the app's public dir or a CDN and points config.circuitBaseUrl at them.
// Proving is O(seconds) in-browser for these 2×2 / 2×1 circuits (not the 50ms server
// figure). This module is the un-tested browser edge; the witness it proves is built
// and unit-tested in spend.ts.

import type { ProvingRequest, Calldata } from "../../../../prover-cli/src/types.js";

async function fetchBytes(url: string): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`asset ${url} -> ${res.status} (is the circuit wasm/zkey served?)`);
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * Prove a transfer/withdraw ProvingRequest in the browser and return the on-chain
 * calldata `(a, b, c, pub)`. `pub` already carries the ciphertext (circuit outputs),
 * so the caller submits it straight to pool.transfer / pool.withdraw (metamask.ts).
 */
export async function proveInBrowser(
  request: ProvingRequest,
  circuitBaseUrl: string,
): Promise<Calldata> {
  if (request.circuit !== "transfer" && request.circuit !== "withdraw") {
    throw new Error(`the public wallet only proves transfer/withdraw in-browser, not ${request.circuit}`);
  }
  const base = circuitBaseUrl.replace(/\/$/, "");
  const [wasm, zkey, snarkjs] = await Promise.all([
    fetchBytes(`${base}/${request.circuit}.wasm`),
    fetchBytes(`${base}/${request.circuit}.zkey`),
    import("snarkjs"),
  ]);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(request.input, wasm, zkey);
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, pub] = JSON.parse("[" + cd + "]");
  return { a, b, c, pub };
}
