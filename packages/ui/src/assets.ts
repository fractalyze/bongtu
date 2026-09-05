// Version-keyed Cache Storage prefetch for the browser Groth16 proving assets
// (SPEC §6 "one-time zkey download", U-W0 measured: transfer.zkey ~27 MB /
// withdraw.zkey ~24 MB, wasm ~3 MB each — far too big to bundle, and re-fetching
// them every proof is the thing that makes an in-browser wallet feel broken).
//
// The strategy:
//   - one Cache Storage bucket per circuit VERSION ("bongtu-circuits-v<hash>"),
//     where <hash> = the first 8 of sha256 over the app's zkeys concatenated
//     (the app config's version) — all the keys the bucket stores, so
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
// (both apps' assets tests drive it through their thin config wrappers).
//
// PARAMETERIZED (issue #46 shared-libs consolidation): this module is generic over
// the app's circuit-name union. Each app binds its own pinned CIRCUITS_VERSION and
// byte table through `createCircuitPrefetch`, so the two apps' DISJOINT circuit
// families stay compile-checked instead of stringly-typed.

/** Exact decoded byte sizes of one circuit's served {wasm, zkey} pair. */
export interface CircuitAssetSizes {
  wasm: number;
  zkey: number;
}

/** What an app pins about its circuit family: the Cache Storage version and the
 *  per-circuit decoded sizes (the download bar's denominator). `Record` over the
 *  app's own circuit union keeps the table exhaustive by construction. */
export interface CircuitAssetConfig<C extends string> {
  version: string;
  assetBytes: Readonly<Record<C, CircuitAssetSizes>>;
}

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
  /** No-chunk-for-this-long aborts the stream (one retry, then throw).
   *  Injectable so the watchdog gates in tests without a 20 s wait. */
  stallMs?: number;
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

// The no-cache fallback: never hits, swallows puts. Downloads still work — the
// banner just returns on the next visit instead of never. Used when Cache Storage
// is unavailable (non-secure context, hard privacy mode) or refuses writes
// (QuotaExceededError on a full device) — caching is an optimisation, not a
// requirement, so neither may break proving.
const NOOP_CACHE: CacheLike = {
  match: () => Promise.resolve(undefined),
  put: () => Promise.resolve(),
};

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
// announce the download, stream the bytes, then store the ASSEMBLED buffer.
//
// Order is load-bearing: never `await cache.put(res.clone())` before reading the
// body. clone() tees the stream, and awaiting the put branch while nobody reads
// the original stalls the whole download at the tee's buffer limit — on the
// 95 MB zkey that was a permanent hang at a few hundred KB (observed live).
// Reading first also means the cache write costs no second pass: put() gets a
// fully-buffered Response.
//
// A stalled network stream (no chunk for STALL_MS) aborts and retries ONCE with
// a fresh fetch; a second stall throws, so the flow's error surface takes over
// instead of an indefinite hang behind disabled buttons.
const STALL_MS = 20_000;

async function cachedFetch(
  cache: CacheLike,
  url: string,
  expectedTotal: number | null,
  deps: PrefetchDeps,
): Promise<ArrayBuffer> {
  const hit = await cache.match(url);
  if (hit) return hit.arrayBuffer();
  deps.onDownloadStart?.(url);
  const bytes = await downloadOnce(url, expectedTotal, deps).catch((e: unknown) => {
    if (!(e instanceof AssetStallError)) throw e;
    return downloadOnce(url, expectedTotal, deps); // one fresh retry
  });
  try {
    await cache.put(url, new Response(bytes));
  } catch {
    // QuotaExceededError (or any storage refusal): keep going without the cache —
    // this download still succeeded; the next visit just re-downloads.
  }
  return bytes;
}

class AssetStallError extends Error {
  constructor(url: string, received: number) {
    super(`download stalled: ${url} stopped after ${received} bytes`);
  }
}

async function downloadOnce(
  url: string,
  expectedTotal: number | null,
  deps: PrefetchDeps,
): Promise<ArrayBuffer> {
  const doFetch = deps.fetchFn ?? fetch;
  const res = await doFetch(url);
  if (!res.ok) throw new Error(`asset ${url} -> ${res.status} (is the circuit wasm/zkey served at ${new URL(url, "http://x").pathname}?)`);
  if (!deps.onProgress || !res.body) return res.arrayBuffer();

  // The pinned decoded size wins over Content-Length: the CDN's header is
  // missing on some assets and counts COMPRESSED bytes on others, while the
  // reader below counts decoded bytes.
  const totalHeader = res.headers.get("content-length");
  const total = expectedTotal ?? (totalHeader ? Number(totalHeader) : null);
  const onProgress = deps.onProgress;
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  const readFrom = async (received: number): Promise<number> => {
    const timer: { id?: ReturnType<typeof setTimeout> } = {};
    const stalled = new Promise<never>((_, reject) => {
      timer.id = setTimeout(() => reject(new AssetStallError(url, received)), deps.stallMs ?? STALL_MS);
    });
    const step = await Promise.race([reader.read(), stalled])
      .catch((e: unknown) => {
        void reader.cancel().catch(() => {});
        throw e;
      })
      .finally(() => clearTimeout(timer.id));
    if (step.done) return received;
    chunks.push(step.value);
    const grown = received + step.value.byteLength;
    onProgress({ url, received: grown, total });
    return readFrom(grown);
  };
  const received = await readFrom(0);
  const out = new Uint8Array(received);
  chunks.reduce((off, c) => {
    out.set(c, off);
    return off + c.byteLength;
  }, 0);
  return out.buffer;
}

/**
 * Bind an app's circuit-family config and get its `prefetchCircuitAssets`: fetch a
 * circuit's `{wasm, zkey}` into the version bucket (evicting stale ones first) and
 * return the kept ArrayBuffers. On a warm cache this is instant and
 * `onDownloadStart` never fires; on a cold cache the caller shows a one-time banner
 * while the ~28 MB zkey downloads. Trigger it on Send/Withdraw screen OPEN so the
 * download overlaps the user typing.
 */
export function createCircuitPrefetch<C extends string>(
  config: CircuitAssetConfig<C>,
): (circuit: C, circuitBaseUrl: string, version?: string, deps?: PrefetchDeps) => Promise<CircuitAssets> {
  return async function prefetchCircuitAssets(
    circuit: C,
    circuitBaseUrl: string,
    version: string = config.version,
    deps: PrefetchDeps = {},
  ): Promise<CircuitAssets> {
    // Any Cache Storage failure at setup (API absent, open refused) degrades to the
    // no-cache path instead of blocking proving.
    const cache: CacheLike = await (async () => {
      try {
        const cs = deps.cacheStorage ?? defaultCacheStorage();
        await evictStaleCaches(version, { ...deps, cacheStorage: cs });
        return await cs.open(cacheNameFor(version));
      } catch {
        return NOOP_CACHE;
      }
    })();
    const base = circuitBaseUrl.replace(/\/$/, "");
    const expected = config.assetBytes[circuit];
    const [wasm, zkey] = await Promise.all([
      cachedFetch(cache, `${base}/${circuit}.wasm`, expected.wasm, deps),
      cachedFetch(cache, `${base}/${circuit}.zkey`, expected.zkey, deps),
    ]);
    return { wasm, zkey };
  };
}
