// This app's browser-proving surface — the thin binding of the shared prover
// (@bongtu/ui/prove, issue #46) to the institution wallet's circuit family. The
// coalesced prefetch, download registry, allow-list gate and snarkjs proving path
// all live in the shared module; this file supplies the pinned config (version,
// byte table, CPU allow-list and its refusal wording) and re-exports the exact
// surface screens and tests always imported from src/lib/prove.ts.
import { createBrowserProver } from "@bongtu/ui/prove";
import { CIRCUITS_VERSION, CIRCUIT_ASSET_BYTES, type BrowserCircuit } from "../config.js";

export { prewarmProver, type CircuitDownloadState } from "@bongtu/ui/prove";

// The circuits the public wallet proves in-browser on CPU (SPEC §6): the spends
// (transfer, its 10-in/2-out form transfer10x2, and withdraw) plus the 0-in/2-out
// deposit/shield. disburse is GPU-only (prover/); transfer10 (10-out) is
// deprecated (2026-07-28) and is no longer a circuit the wallet proves.
const CPU_CIRCUITS: readonly BrowserCircuit[] = ["transfer", "transfer10x2", "withdraw", "deposit"];

const prover = createBrowserProver<BrowserCircuit>({
  version: CIRCUITS_VERSION,
  assetBytes: CIRCUIT_ASSET_BYTES,
  cpuCircuits: CPU_CIRCUITS,
  notCpuMessage: (circuit) =>
    `the public wallet only proves transfer/transfer10x2/withdraw/deposit in-browser, not ${circuit}`,
});

export const subscribeCircuitDownload = prover.subscribeCircuitDownload;
export const ensureCircuitAssets = prover.ensureCircuitAssets;
export const proveInBrowser = prover.proveInBrowser;

/** Whether `circuit` is one the wallet proves in-browser. The deprecated
 *  transfer10 deliberately fails this check: its assets left the download set,
 *  so proving it could only ever 404. */
export const isCpuCircuit: (circuit: string) => circuit is BrowserCircuit = prover.isCpuCircuit;

export const assertCpuCircuit: (circuit: string) => asserts circuit is BrowserCircuit =
  prover.assertCpuCircuit;
