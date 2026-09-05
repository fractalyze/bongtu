// Browser Groth16 proving for an app's small CPU circuits (SPEC §6 transfer proving).
//
// GPL DECISION (SPEC §6, explicit): shipping snarkjs to the page IS distribution
// (no server-side isolation applies here — and a self-custody wallet must never
// send spending-key witnesses to a server anyway). The PoC takes option (a): accept
// GPL-3.0 for the public app, documented in README. snarkjs is dynamically imported
// so it only loads when the user actually proves.
//
// ASSET BOUNDARY (SPEC §6 "one-time zkey download"): the wasm + zkey for each
// browser-proved circuit are served as static assets at `${circuitBaseUrl}/<circuit>.wasm`
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
// unit-tested in @bongtu/client, and the asset caching is unit-tested per app.
//
// PARAMETERIZED (issue #46 shared-libs consolidation): the two apps prove DISJOINT
// circuit families (treasury: transfer/transfer10x2/withdraw/deposit; wallet: the
// four *Priv ops), so the whole flow — allow-list, download registry, prefetch,
// proving — is built per app by `createBrowserProver` over the app's own circuit
// union and pinned config. Each app's thin src/lib/prove.ts binds it and re-exports
// the surface its screens and tests always imported.

import type { ProvingRequest, Calldata } from "@bongtu/core/proving";
import {
  createCircuitPrefetch,
  type AssetDownloadProgress,
  type CircuitAssetConfig,
  type CircuitAssets,
  type PrefetchDeps,
} from "./assets.js";

/** The live download of one circuit's assets: per-URL byte progress + start time
 *  (the ETA is rate-derived by the UI hook). */
export interface CircuitDownloadState {
  startedAt: number;
  assets: Record<string, AssetDownloadProgress>;
}

/** What an app pins to get a browser prover: the asset config (version + byte
 *  table) plus its CPU allow-list and the refusal wording for anything else.
 *  `cpuCircuits` is typed on the app's own union, so a foreign circuit name is a
 *  tsc error in the app's binding, not a runtime surprise. */
export interface BrowserProverConfig<C extends string> extends CircuitAssetConfig<C> {
  cpuCircuits: readonly C[];
  /** The message `assertCpuCircuit` throws — each app words its own allow-list
   *  refusal (its tests pin the wording). */
  notCpuMessage: (circuit: string) => string;
}

/** The per-app proving surface `createBrowserProver` returns. */
export interface BrowserProver<C extends string> {
  isCpuCircuit(circuit: string): circuit is C;
  assertCpuCircuit(circuit: string): asserts circuit is C;
  subscribeCircuitDownload(circuit: C, cb: (s: CircuitDownloadState | null) => void): () => void;
  ensureCircuitAssets(circuit: C, circuitBaseUrl: string, deps?: PrefetchDeps): Promise<CircuitAssets>;
  proveInBrowser(request: ProvingRequest, circuitBaseUrl: string, deps?: PrefetchDeps): Promise<Calldata>;
}

/**
 * Best-effort bn128 pre-warm: build the curve via ffjavascript then immediately
 * terminate it. We DON'T keep the curve (snarkjs builds its own per proof) — the point
 * is to pay the one-time WASM compile + worker spin-up during the asset prefetch, so
 * the browser's compiled-module cache is warm when the real proof builds its curve.
 * NON-FATAL by contract: any failure (module shape drift, no threads) is swallowed —
 * never blocks the UI; a cold curve on the first proof is the fallback.
 *
 * Takes no circuit argument on purpose: it warms only the SHARED bn128 curve, which is
 * identical across every browser-proved circuit — the per-circuit wasm/zkey are prefetched
 * separately by ensureCircuitAssets. Config-free, so it lives outside the factory.
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
 * Build an app's browser prover over its own circuit union. All the state that used
 * to sit at module level in each app's prove.ts (the in-flight prefetch coalescing,
 * the download registry) lives in this closure — one instance per app binding, the
 * same lifetime it always had.
 */
export function createBrowserProver<C extends string>(config: BrowserProverConfig<C>): BrowserProver<C> {
  const prefetchCircuitAssets = createCircuitPrefetch(config);

  // Session-scoped in-flight prefetch, one per circuit: the version-keyed Cache Storage
  // bucket survives a restart (disk), and caching the PROMISE (not just the resolved
  // value) coalesces the two calls React StrictMode fires on mount into one download.
  const inflight: Partial<Record<C, Promise<CircuitAssets>>> = {};

  // -------------------------------------------------------------------------------
  // Download-state registry. Because the prefetch promise is coalesced, only the FIRST
  // caller's PrefetchDeps callbacks are wired — a screen that (re)mounts mid-download
  // would show nothing and leave its buttons enabled while 28 MB stream in. So the
  // live download state is kept HERE, per circuit, and screens subscribe: on attach
  // the current state replays immediately, every chunk updates it, resolution clears
  // it (state null == no active download; the UI hides the bar and re-enables).
  // -------------------------------------------------------------------------------
  const downloadState: Partial<Record<C, CircuitDownloadState>> = {};
  const downloadListeners: Partial<Record<C, Set<(s: CircuitDownloadState | null) => void>>> = {};

  const emitDownload = (circuit: C): void => {
    const s = downloadState[circuit] ?? null;
    for (const cb of downloadListeners[circuit] ?? []) cb(s);
  };

  /** Subscribe to a circuit's live download state (null == none active). The current
   *  state is replayed synchronously on subscribe, so a screen attaching mid-download
   *  renders the bar (and disables its actions) immediately. Returns unsubscribe. */
  const subscribeCircuitDownload = (
    circuit: C,
    cb: (s: CircuitDownloadState | null) => void,
  ): (() => void) => {
    (downloadListeners[circuit] ??= new Set()).add(cb);
    cb(downloadState[circuit] ?? null);
    return () => downloadListeners[circuit]?.delete(cb);
  };

  /** Whether `circuit` is one this app proves in-browser. A circuit outside the
   *  app's allow-list deliberately fails this check: its assets are not in this
   *  app's download set, so proving it could only ever 404. */
  const isCpuCircuit = (circuit: string): circuit is C =>
    (config.cpuCircuits as readonly string[]).includes(circuit);

  const assertCpuCircuit: (circuit: string) => asserts circuit is C = (circuit) => {
    if (!isCpuCircuit(circuit)) throw new Error(config.notCpuMessage(circuit));
  };

  /** Ensure a circuit's `{wasm, zkey}` are downloaded and kept for the session. Idempotent
   *  and cheap once warm. Call it on Send/Withdraw screen OPEN so the ~28 MB download
   *  overlaps the user typing; `deps.onDownloadStart` drives the first-run banner. */
  const ensureCircuitAssets = async (
    circuit: C,
    circuitBaseUrl: string,
    deps: PrefetchDeps = {},
  ): Promise<CircuitAssets> => {
    const pending = inflight[circuit];
    if (pending) return pending;
    const p = prefetchCircuitAssets(circuit, circuitBaseUrl, config.version, {
      ...deps,
      onDownloadStart: (url) => {
        downloadState[circuit] ??= { startedAt: Date.now(), assets: {} };
        // Seed the total from the pinned byte table, not the stream: the view's
        // aggregate only shows percent/ETA once EVERY in-flight asset has a total,
        // and the 95 MB zkey's first chunk can lag the wasm by seconds — a null
        // here is exactly the "0.1 MB, no bar" hang the card exists to prevent.
        const pinned = config.assetBytes[circuit];
        const total = url.endsWith(".wasm") ? pinned.wasm : url.endsWith(".zkey") ? pinned.zkey : null;
        downloadState[circuit].assets[url] = { url, received: 0, total };
        emitDownload(circuit);
        deps.onDownloadStart?.(url);
      },
      onProgress: (progress) => {
        const s = downloadState[circuit];
        if (s) {
          s.assets[progress.url] = progress;
          emitDownload(circuit);
        }
        deps.onProgress?.(progress);
      },
    });
    inflight[circuit] = p;
    try {
      return await p;
    } catch (e) {
      // drop the rejected promise so a later open retries instead of re-throwing forever.
      delete inflight[circuit];
      throw e;
    } finally {
      delete downloadState[circuit];
      emitDownload(circuit);
    }
  };

  /** Prove a ProvingRequest in the browser and return the on-chain calldata
   *  `(a, b, c, pub)`. `pub` already carries the ciphertext (circuit outputs), so the
   *  caller submits it straight to the pool. Uses the KEPT wasm/zkey buffers (via
   *  `ensureCircuitAssets`) and the two-step witness→prove path, so the zkey is not
   *  re-fetched per proof. */
  const proveInBrowser = async (
    request: ProvingRequest,
    circuitBaseUrl: string,
    deps: PrefetchDeps = {},
  ): Promise<Calldata> => {
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
  };

  return {
    isCpuCircuit,
    assertCpuCircuit,
    subscribeCircuitDownload,
    ensureCircuitAssets,
    proveInBrowser,
  };
}
