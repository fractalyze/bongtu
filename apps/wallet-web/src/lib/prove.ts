// This app's browser-proving surface — the thin binding of the shared prover
// (@bongtu/ui/prove, issue #46) to the consumer wallet's circuit family. The
// coalesced prefetch, download registry, allow-list gate and snarkjs proving path
// all live in the shared module; this file supplies the pinned config (version,
// byte table, CPU allow-list and its refusal wording) and re-exports the exact
// surface screens and tests always imported from src/lib/prove.ts.
import { createBrowserProver } from "@bongtu/ui/prove";
import { CIRCUITS_VERSION, CIRCUIT_ASSET_BYTES, type BrowserCircuit } from "../config.js";

export { prewarmProver, type CircuitDownloadState } from "@bongtu/ui/prove";

// The circuits the consumer wallet proves in-browser on CPU: exactly the P2P 4-op
// family (config.ts BrowserCircuit) — the spends (transferPriv, its 10-in/2-out
// form transfer10x2Priv, and withdrawPriv) plus the 0-in/2-out depositPriv mint.
// Nothing else is provable from this bundle by construction.
const CPU_CIRCUITS: readonly BrowserCircuit[] = ["depositPriv", "transferPriv", "transfer10x2Priv", "withdrawPriv"];

const prover = createBrowserProver<BrowserCircuit>({
  version: CIRCUITS_VERSION,
  assetBytes: CIRCUIT_ASSET_BYTES,
  cpuCircuits: CPU_CIRCUITS,
  notCpuMessage: (circuit) =>
    `the consumer wallet only proves depositPriv/transferPriv/transfer10x2Priv/withdrawPriv in-browser, not ${circuit}`,
});

export const subscribeCircuitDownload = prover.subscribeCircuitDownload;
export const ensureCircuitAssets = prover.ensureCircuitAssets;
export const proveInBrowser = prover.proveInBrowser;

/** Whether `circuit` is one the consumer wallet proves in-browser. The
 *  enterprise-family circuits deliberately fail this check: their assets are not
 *  in this app's download set, so proving one could only ever 404. */
export const isCpuCircuit: (circuit: string) => circuit is BrowserCircuit = prover.isCpuCircuit;

export const assertCpuCircuit: (circuit: string) => asserts circuit is BrowserCircuit =
  prover.assertCpuCircuit;
