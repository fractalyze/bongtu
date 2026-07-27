// Version-keyed Cache Storage prefetch for the browser Groth16 proving assets
// (SPEC §6 "one-time zkey download", U-W0 measured: transfer.zkey ~27 MB /
// withdraw.zkey ~24 MB, wasm ~3 MB each — far too big to bundle, and re-fetching
// them every proof is the thing that makes an in-browser wallet feel broken).
//
// The strategy:
//   - one Cache Storage bucket per circuit VERSION ("bongtu-circuits-v<hash>"),
//     where <hash> = the first 8 of sha256(transfer.zkey || withdraw.zkey ||
//     deposit.zkey) (config.CIRCUITS_VERSION) — all three keys the bucket stores, so
//     regenerating any one changes the version. The bucket is disk-backed, so a warmed
//     key survives a browser restart.
//   - on prefetch, evict any OTHER "bongtu-circuits-*" bucket: when the circuit is
//     re-proven the version changes and the stale key must not be served (it would
//     fail on-chain verify), so the browser silently re-downloads the new one.
//   - a cache MISS is the only time the network is touched; the caller shows the
//     first-run "downloading ~28 MB" banner via `onDownloadStart`, and on a warm
//     cache the banner never appears.
//
// The two selection helpers (`cacheNameFor`, `staleCacheKeys`) are pure and the
// whole flow is driven through injectable `CacheStorageLike` / `fetchFn`, so the
// eviction + hit/miss behaviour is unit-tested with an in-memory fake — no browser
// (test/assets.test.ts). This is the genuinely NEW behaviour this unit adds.

import { CIRCUITS_VERSION, CIRCUIT_ASSET_BYTES } from "../config.js";

/** The shared family prefix every circuit-asset bucket carries. Eviction keeps the
 *  current version's bucket and deletes the rest of this family; unrelated caches
 *  (a service-worker precache, someone else's app) are never touched. */
const CACHE_FAMILY = "bongtu-circuits-";

/** The Cache Storage bucket name for a circuit version: `bongtu-circuits-v<version>`. */
export function cacheNameFor(version: string): string {
  return CACHE_FAMILY + "v" + version;
}

/**
 * Of `existing` cache keys, the ones to evict for `version`: every member of the
 * `bongtu-circuits-` family that is NOT the current bucket. PURE — the current
 * bucket is kept and non-family keys are left untouched.
 */
export function staleCacheKeys(existing: readonly string[], version: string): string[] {
  const current = cacheNameFor(version);
  return existing.filter((k) => k.startsWith(CACHE_FAMILY) && k !== current);
}

// --- injectable browser-API surface (so the flow is testable headlessly) ---------

/** The subset of the browser `Cache` the prefetch uses. */
export interface CacheLike {
  match(request: string): Promise<Response | undefined>;
  put(request: string, response: Response): Promise<void>;
}

/** The subset of the browser `CacheStorage` (`caches`) the prefetch uses. */
export interface CacheStorageLike {
  open(cacheName: string): Promise<CacheLike>;
  keys(): Promise<string[]>;
  delete(cacheName: string): Promise<boolean>;
}

/** Byte-level progress of one asset download (a cache MISS being fetched). */
export interface AssetDownloadProgress {
  url: string;
  received: number;
  /** Total bytes from Content-Length; null when the server doesn't send it
   *  (the UI then shows an indeterminate bar, no ETA). */
  total: number | null;
}

export interface PrefetchDeps {
  /** Defaults to the global `caches`. Injected as an in-memory fake in tests. */
  cacheStorage?: CacheStorageLike;
  /** Defaults to the global `fetch`. Injected in tests. */
  fetchFn?: (url: string) => Promise<Response>;
  /** Fires once per asset that MISSES the cache — i.e. a real network download
   *  begins. The UI shows the first-run "downloading proving key" banner on the
   *  first such call and clears it when the prefetch promise resolves. */
  onDownloadStart?: (url: string) => void;
  /** Fires per received chunk of a MISSED asset — drives the progress bar + ETA.
   *  Never fires on a cache hit. */
  onProgress?: (progress: AssetDownloadProgress) => void;
}

/** The kept in-memory buffers for one circuit — reused across a session's proofs. */
export interface CircuitAssets {
  wasm: ArrayBuffer;
  zkey: ArrayBuffer;
}

function defaultCacheStorage(): CacheStorageLike {
  const cs = (globalThis as { caches?: CacheStorageLike }).caches;
  if (!cs) throw new Error("Cache Storage API unavailable (needs a browser secure context)");
  return cs;
}

/**
 * Delete every stale `bongtu-circuits-*` bucket, keeping only `version`'s. Returns
 * the deleted names. Safe to call before every prefetch (a no-op once warm).
 */
export async function evictStaleCaches(version: string, deps: PrefetchDeps = {}): Promise<string[]> {
  const cs = deps.cacheStorage ?? defaultCacheStorage();
  const stale = staleCacheKeys(await cs.keys(), version);
  await Promise.all(stale.map((k) => cs.delete(k)));
  return stale;
}

// One asset: serve it from the version bucket on a hit; on a miss download it,
// announce the download, store a clone, and return the bytes. A Response body is
// single-use, so we `put` a clone and read the bytes from the original — via a
// streaming reader when progress is wanted (per-chunk onProgress with the
// Content-Length total), else the plain arrayBuffer path.
async function cachedFetch(
  cache: CacheLike,
  url: string,
  expectedTotal: number | null,
  deps: PrefetchDeps,
): Promise<ArrayBuffer> {
  const hit = await cache.match(url);
  if (hit) return hit.arrayBuffer();
  deps.onDownloadStart?.(url);
  const doFetch = deps.fetchFn ?? fetch;
  const res = await doFetch(url);
  if (!res.ok) throw new Error(`asset ${url} -> ${res.status} (is the circuit wasm/zkey served at ${new URL(url, "http://x").pathname}?)`);
  await cache.put(url, res.clone());
  if (!deps.onProgress || !res.body) return res.arrayBuffer();

  // The pinned decoded size wins over Content-Length: the CDN's header is
  // missing on some assets and counts COMPRESSED bytes on others, while the
  // reader below counts decoded bytes.
  const totalHeader = res.headers.get("content-length");
  const total = expectedTotal ?? (totalHeader ? Number(totalHeader) : null);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.byteLength;
    deps.onProgress({ url, received, total });
  }
  const out = new Uint8Array(received);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out.buffer;
}

/**
 * Prefetch a circuit's `{wasm, zkey}` into the version bucket (evicting stale ones
 * first) and return the kept ArrayBuffers. On a warm cache this is instant and
 * `onDownloadStart` never fires; on a cold cache the caller shows a one-time banner
 * while the ~28 MB zkey downloads. Trigger it on Send/Withdraw screen OPEN so the
 * download overlaps the user typing.
 */
export async function prefetchCircuitAssets(
  circuit: "transfer" | "withdraw" | "deposit",
  circuitBaseUrl: string,
  version: string = CIRCUITS_VERSION,
  deps: PrefetchDeps = {},
): Promise<CircuitAssets> {
  const cs = deps.cacheStorage ?? defaultCacheStorage();
  const depsWithCs: PrefetchDeps = { ...deps, cacheStorage: cs };
  await evictStaleCaches(version, depsWithCs);
  const cache = await cs.open(cacheNameFor(version));
  const base = circuitBaseUrl.replace(/\/$/, "");
  const expected = CIRCUIT_ASSET_BYTES[circuit];
  const [wasm, zkey] = await Promise.all([
    cachedFetch(cache, `${base}/${circuit}.wasm`, expected.wasm, depsWithCs),
    cachedFetch(cache, `${base}/${circuit}.zkey`, expected.zkey, depsWithCs),
  ]);
  return { wasm, zkey };
}
