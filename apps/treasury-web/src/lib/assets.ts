// This app's proving-asset prefetch — the thin binding of the shared version-keyed
// Cache Storage prefetch (@bongtu/ui/assets, issue #46) to the institution wallet's
// circuit family (transfer/transfer10x2/withdraw/deposit) and its pinned
// CIRCUITS_VERSION. Flow logic, eviction rules and the injectable browser surface
// live in the shared module; this file supplies the config and keeps the app's
// import surface (test/assets.test.ts drives the flow through these exact names).
import { createCircuitPrefetch, type CircuitAssets, type PrefetchDeps } from "@bongtu/ui/assets";
import { CIRCUITS_VERSION, CIRCUIT_ASSET_BYTES, type BrowserCircuit } from "../config.js";

export {
  cacheNameFor,
  evictStaleCaches,
  staleCacheKeys,
  type AssetDownloadProgress,
  type CacheLike,
  type CacheStorageLike,
  type CircuitAssets,
  type PrefetchDeps,
} from "@bongtu/ui/assets";

const prefetch = createCircuitPrefetch<BrowserCircuit>({
  version: CIRCUITS_VERSION,
  assetBytes: CIRCUIT_ASSET_BYTES,
});

/**
 * Prefetch a circuit's `{wasm, zkey}` into the version bucket (evicting stale ones
 * first) and return the kept ArrayBuffers — the exact contract this path always had;
 * the flow itself lives in the shared module.
 */
export function prefetchCircuitAssets(
  circuit: BrowserCircuit,
  circuitBaseUrl: string,
  version: string = CIRCUITS_VERSION,
  deps: PrefetchDeps = {},
): Promise<CircuitAssets> {
  return prefetch(circuit, circuitBaseUrl, version, deps);
}
