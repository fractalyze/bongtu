// Browser Groth16 proving for the two small CPU circuits (SPEC §6 transfer proving).
//
// GPL DECISION (SPEC §6, explicit): shipping snarkjs to the page IS distribution
// (no server-side isolation applies here — and a self-custody wallet must never
// send spending-key witnesses to a server anyway). The PoC takes option (a): accept
// GPL-3.0 for the public app, documented in README. snarkjs is dynamically imported
// so it only loads when the user actually proves.
//
// ASSET BOUNDARY (SPEC §6 "one-time zkey download"): the wasm + zkey for
// transfer/withdraw are served as static assets at `${circuitBaseUrl}/<circuit>.wasm`
// and `.zkey` (NOT bundled — transfer.zkey ~28 MB). `assets.ts` fetches them once into
// a version-keyed Cache Storage bucket; this module KEEPS the returned ArrayBuffers on
// the session and proves against them with the two-step `wtns.calculate` +
// `groth16.prove` path (what `groth16.fullProve` does internally), so a session's
// second proof re-uses the in-memory zkey BYTES instead of re-downloading 28 MB.
// (snarkjs still re-parses the zkey each proof — the win is avoiding the network.)
//
// U-W0 measured (headless Chromium, real): a WARM transfer proof is 3.5–5.4 s on a
// 24-thread desktop; budget 7–20 s on a laptop. COOP/COEP had ZERO effect (not set).
// This module is the un-tested browser edge; the witness it proves is built and
// unit-tested in spend.ts, and the asset caching is unit-tested in assets.test.ts.

import type { ProvingRequest, Calldata } from "@bongtu/core/proving";
import { CIRCUITS_VERSION } from "../config.js";
import { prefetchCircuitAssets, type CircuitAssets, type PrefetchDeps } from "./assets.js";

type CpuCircuit = "transfer" | "withdraw";

// Session-scoped in-flight prefetch, one per circuit: the version-keyed Cache Storage
// bucket survives a restart (disk), and caching the PROMISE (not just the resolved
// value) coalesces the two calls React StrictMode fires on mount into one download.
const inflight: Partial<Record<CpuCircuit, Promise<CircuitAssets>>> = {};

function assertCpuCircuit(circuit: string): asserts circuit is CpuCircuit {
  if (circuit !== "transfer" && circuit !== "withdraw") {
    throw new Error(`the public wallet only proves transfer/withdraw in-browser, not ${circuit}`);
  }
}

/**
 * Ensure a circuit's `{wasm, zkey}` are downloaded and kept for the session. Idempotent
 * and cheap once warm. Call it on Send/Withdraw screen OPEN so the ~28 MB download
 * overlaps the user typing; `deps.onDownloadStart` drives the first-run banner.
 */
export async function ensureCircuitAssets(
  circuit: CpuCircuit,
  circuitBaseUrl: string,
  deps: PrefetchDeps = {},
): Promise<CircuitAssets> {
  const pending = inflight[circuit];
  if (pending) return pending;
  const p = prefetchCircuitAssets(circuit, circuitBaseUrl, CIRCUITS_VERSION, deps);
  inflight[circuit] = p;
  try {
    return await p;
  } catch (e) {
    // drop the rejected promise so a later open retries instead of re-throwing forever.
    delete inflight[circuit];
    throw e;
  }
}

/**
 * Best-effort bn128 pre-warm: build the curve via ffjavascript then immediately
 * terminate it. We DON'T keep the curve (snarkjs builds its own per proof) — the point
 * is to pay the one-time WASM compile + worker spin-up during the asset prefetch, so
 * the browser's compiled-module cache is warm when the real proof builds its curve.
 * NON-FATAL by contract: any failure (module shape drift, no threads) is swallowed —
 * never blocks the UI; a cold curve on the first proof is the fallback.
 */
export async function prewarmProver(): Promise<void> {
  try {
    const ff = (await import("ffjavascript")) as { buildBn128?: () => Promise<{ terminate?: () => Promise<void> }> };
    if (typeof ff.buildBn128 !== "function") return;
    const curve = await ff.buildBn128();
    await curve.terminate?.();
  } catch {
    // best-effort only — a cold curve init on the first proof is the fallback.
  }
}

/**
 * Prove a transfer/withdraw ProvingRequest in the browser and return the on-chain
 * calldata `(a, b, c, pub)`. `pub` already carries the ciphertext (circuit outputs),
 * so the caller submits it straight to pool.transfer / pool.withdraw (metamask.ts).
 *
 * Uses the KEPT wasm/zkey buffers (via `ensureCircuitAssets`) and the two-step
 * witness→prove path, so the zkey is not re-fetched per proof. Same external contract
 * as before: same ProvingRequest in, same Calldata out.
 */
export async function proveInBrowser(
  request: ProvingRequest,
  circuitBaseUrl: string,
  deps: PrefetchDeps = {},
): Promise<Calldata> {
  assertCpuCircuit(request.circuit);
  const [{ wasm, zkey }, snarkjs] = await Promise.all([
    ensureCircuitAssets(request.circuit, circuitBaseUrl, deps),
    import("snarkjs"),
  ]);
  // A fresh in-memory witness handle per proof; snarkjs writes it, then proves it.
  const wtns: import("snarkjs").MemWtns = { type: "mem" };
  await snarkjs.wtns.calculate(request.input, new Uint8Array(wasm), wtns);
  const { proof, publicSignals } = await snarkjs.groth16.prove(new Uint8Array(zkey), wtns);
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, pub] = JSON.parse("[" + cd + "]");
  return { a, b, c, pub };
}
