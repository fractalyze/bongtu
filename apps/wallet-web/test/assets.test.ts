// Headless gates for the NEW browser-proving asset cache (src/lib/assets.ts) — the
// version-keyed Cache Storage prefetch this unit adds. The two selection helpers are
// pure; the hit/miss + eviction flow is driven through an in-memory fake
// CacheStorage (no browser), so we prove the load-bearing behaviour without a DOM:
//
//   (1) cache NAME derivation is version-keyed and family-prefixed;
//   (2) STALE-eviction selects exactly the other-version family buckets — keeping the
//       current one and never touching unrelated caches (a re-proven zkey must force a
//       one-time re-download, but must not nuke a service-worker precache);
//   (3) a cold prefetch MISSES → downloads → announces once per asset → stores; a warm
//       prefetch HITS → no network, no onDownloadStart (the thing that makes the wallet
//       feel instant on the second proof).

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  cacheNameFor,
  staleCacheKeys,
  evictStaleCaches,
  prefetchCircuitAssets,
  type CacheLike,
  type CacheStorageLike,
} from "../src/lib/assets.js";
import { CIRCUIT_ASSET_BYTES } from "../src/config.js";

// --- in-memory fake of the browser Cache Storage surface the prefetch uses --------

class FakeCache implements CacheLike {
  readonly store = new Map<string, ArrayBuffer>();
  async match(request: string): Promise<Response | undefined> {
    const buf = this.store.get(request);
    return buf === undefined ? undefined : new Response(buf);
  }
  async put(request: string, response: Response): Promise<void> {
    this.store.set(request, await response.arrayBuffer());
  }
}

class FakeCacheStorage implements CacheStorageLike {
  readonly caches = new Map<string, FakeCache>();
  async open(cacheName: string): Promise<CacheLike> {
    let c = this.caches.get(cacheName);
    if (!c) {
      c = new FakeCache();
      this.caches.set(cacheName, c);
    }
    return c;
  }
  async keys(): Promise<string[]> {
    return [...this.caches.keys()];
  }
  async delete(cacheName: string): Promise<boolean> {
    return this.caches.delete(cacheName);
  }
  // seed a pre-existing bucket (as if a prior version had been warmed)
  seed(cacheName: string): void {
    this.caches.set(cacheName, new FakeCache());
  }
}

function bytesResponse(n: number): Response {
  return new Response(new Uint8Array(n).fill(7));
}

// --- (1) cache name derivation ----------------------------------------------------

test("cacheNameFor is version-keyed and family-prefixed", () => {
  assert.equal(cacheNameFor("88542b90"), "bongtu-circuits-v88542b90");
  assert.notEqual(cacheNameFor("88542b90"), cacheNameFor("deadbeef"));
  // every bucket shares the family prefix eviction scans for
  assert.ok(cacheNameFor("anything").startsWith("bongtu-circuits-"));
});

// --- (2) stale-eviction selection -------------------------------------------------

test("staleCacheKeys keeps the current bucket and only evicts other family members", () => {
  const existing = [
    "bongtu-circuits-v88542b90", // current — keep
    "bongtu-circuits-vdeadbeef", // old version — evict
    "bongtu-circuits-v00000000", // older version — evict
    "workbox-precache-v2", // unrelated — never touch
    "some-other-cache", // unrelated — never touch
  ];
  const stale = staleCacheKeys(existing, "88542b90");
  assert.deepEqual(stale.sort(), ["bongtu-circuits-v00000000", "bongtu-circuits-vdeadbeef"]);
});

test("staleCacheKeys is empty when only the current (or no) family bucket exists", () => {
  assert.deepEqual(staleCacheKeys(["bongtu-circuits-v88542b90", "other"], "88542b90"), []);
  assert.deepEqual(staleCacheKeys(["other"], "88542b90"), []);
});

test("evictStaleCaches deletes exactly the stale family buckets via the fake storage", async () => {
  const cs = new FakeCacheStorage();
  cs.seed("bongtu-circuits-v88542b90"); // current
  cs.seed("bongtu-circuits-vdeadbeef"); // stale
  cs.seed("workbox-precache-v2"); // unrelated

  const deleted = await evictStaleCaches("88542b90", { cacheStorage: cs });

  assert.deepEqual(deleted, ["bongtu-circuits-vdeadbeef"]);
  assert.deepEqual((await cs.keys()).sort(), ["bongtu-circuits-v88542b90", "workbox-precache-v2"]);
});

// --- (3) cold miss downloads once; warm hit is silent -----------------------------

test("cold prefetch downloads both assets, announces each once, and stores them", async () => {
  const cs = new FakeCacheStorage();
  const downloads: string[] = [];
  const fetched: string[] = [];
  const fetchFn = async (url: string): Promise<Response> => {
    fetched.push(url);
    return bytesResponse(url.endsWith(".zkey") ? 32 : 8);
  };

  const { wasm, zkey } = await prefetchCircuitAssets("transfer", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn,
    onDownloadStart: (u) => downloads.push(u),
  });

  assert.equal(wasm.byteLength, 8);
  assert.equal(zkey.byteLength, 32);
  assert.deepEqual(fetched.sort(), ["/circuits/transfer.wasm", "/circuits/transfer.zkey"]);
  // one download announcement per missing asset (drives the first-run banner)
  assert.deepEqual(downloads.sort(), ["/circuits/transfer.wasm", "/circuits/transfer.zkey"]);
  // both are now resident in the version bucket
  const bucket = cs.caches.get("bongtu-circuits-v88542b90");
  assert.ok(bucket && bucket.store.size === 2);
});

test("warm prefetch serves from cache with no network and no download announcement", async () => {
  const cs = new FakeCacheStorage();
  const fetchFn = async (url: string): Promise<Response> =>
    bytesResponse(url.endsWith(".zkey") ? 32 : 8);

  // first (cold) run populates the bucket
  await prefetchCircuitAssets("withdraw", "/circuits", "88542b90", { cacheStorage: cs, fetchFn });

  // second (warm) run must not touch the network nor announce a download
  const downloads: string[] = [];
  let calls = 0;
  const { wasm, zkey } = await prefetchCircuitAssets("withdraw", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn: async (url: string) => {
      calls++;
      return bytesResponse(url.endsWith(".zkey") ? 32 : 8);
    },
    onDownloadStart: (u) => downloads.push(u),
  });

  assert.equal(calls, 0, "warm cache must not fetch");
  assert.deepEqual(downloads, [], "warm cache must not announce a download");
  assert.equal(wasm.byteLength, 8);
  assert.equal(zkey.byteLength, 32);
});

test("cold prefetch of the deposit circuit downloads deposit.wasm + deposit.zkey once", async () => {
  // The deposit/shield circuit is the third CPU circuit this app proves in-browser; its
  // assets must prefetch through the same version-keyed path as transfer/withdraw.
  const cs = new FakeCacheStorage();
  const downloads: string[] = [];
  const fetched: string[] = [];
  const fetchFn = async (url: string): Promise<Response> => {
    fetched.push(url);
    return bytesResponse(url.endsWith(".zkey") ? 32 : 8);
  };

  const { wasm, zkey } = await prefetchCircuitAssets("deposit", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn,
    onDownloadStart: (u) => downloads.push(u),
  });

  assert.equal(wasm.byteLength, 8);
  assert.equal(zkey.byteLength, 32);
  assert.deepEqual(fetched.sort(), ["/circuits/deposit.wasm", "/circuits/deposit.zkey"]);
  assert.deepEqual(downloads.sort(), ["/circuits/deposit.wasm", "/circuits/deposit.zkey"]);

  // warm re-run of deposit must not touch the network nor announce a download.
  let calls = 0;
  const warmDownloads: string[] = [];
  await prefetchCircuitAssets("deposit", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn: async (url: string) => {
      calls++;
      return bytesResponse(url.endsWith(".zkey") ? 32 : 8);
    },
    onDownloadStart: (u) => warmDownloads.push(u),
  });
  assert.equal(calls, 0, "warm deposit cache must not fetch");
  assert.deepEqual(warmDownloads, [], "warm deposit cache must not announce a download");
});

test("prefetch evicts a stale-version bucket before serving the current one", async () => {
  const cs = new FakeCacheStorage();
  cs.seed("bongtu-circuits-vOLDVERSION");
  const fetchFn = async (url: string): Promise<Response> =>
    bytesResponse(url.endsWith(".zkey") ? 32 : 8);

  await prefetchCircuitAssets("transfer", "/circuits", "88542b90", { cacheStorage: cs, fetchFn });

  const keys = (await cs.keys()).sort();
  assert.deepEqual(keys, ["bongtu-circuits-v88542b90"], "stale version bucket must be gone");
});

// --- (4) streamed miss reports per-chunk progress ---------------------------------

test("cold prefetch streams progress (received grows, total = Content-Length); warm hit stays silent", async () => {
  const cs = new FakeCacheStorage();
  // A 3-chunk streamed body with an honest Content-Length — the shape a static
  // server serves the ~28 MB zkey with; progress must grow per chunk up to it.
  const streamed = (n: number, chunk: number): Response => {
    let sent = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        if (sent >= n) return c.close();
        const size = Math.min(chunk, n - sent);
        c.enqueue(new Uint8Array(size).fill(7));
        sent += size;
      },
    });
    return new Response(body, { headers: { "content-length": String(n) } });
  };
  const progress: { url: string; received: number; total: number | null }[] = [];
  const { wasm, zkey } = await prefetchCircuitAssets("transfer", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn: async (url: string) => streamed(url.endsWith(".zkey") ? 32 : 8, 16),
    onProgress: (p) => progress.push(p),
  });

  assert.equal(wasm.byteLength, 8, "streamed chunks reassemble to the full wasm");
  assert.equal(zkey.byteLength, 32, "streamed chunks reassemble to the full zkey");
  const zk = progress.filter((p) => p.url === "/circuits/transfer.zkey");
  assert.deepEqual(zk.map((p) => p.received), [16, 32], "received grows per chunk");
  // The pinned decoded size beats Content-Length (the CDN strips it on some
  // assets and reports compressed bytes on others) — the bar always has a total.
  assert.ok(zk.every((p) => p.total === CIRCUIT_ASSET_BYTES.transfer.zkey), "total is the pinned size");

  // warm second run: cache hit, zero progress events
  const warm: string[] = [];
  await prefetchCircuitAssets("transfer", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn: async () => {
      throw new Error("warm cache must not fetch");
    },
    onProgress: (p) => warm.push(p.url),
  });
  assert.deepEqual(warm, [], "a cache hit reports no progress");
});

test("CIRCUIT_ASSET_BYTES matches the assets actually served from public/circuits", () => {
  // The pinned sizes are the progress bar's denominator; a circuit regen that
  // forgets to re-pin them shows a wrong percentage with no other symptom. The
  // assets are gitignored (only the dev/deploy box has them), so absence — the
  // CI case — is a skip, not a pass.
  const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "public", "circuits");
  for (const circuit of ["transfer", "withdraw", "deposit"] as const) {
    for (const kind of ["wasm", "zkey"] as const) {
      const p = join(dir, `${circuit}.${kind}`);
      if (!existsSync(p)) continue;
      assert.equal(
        statSync(p).size,
        CIRCUIT_ASSET_BYTES[circuit][kind],
        `${circuit}.${kind} size drifted from CIRCUIT_ASSET_BYTES — re-pin alongside CIRCUITS_VERSION`,
      );
    }
  }
});

// --- (4) storage-failure fallback (device cache must never block proving) ---------

test("a QuotaExceeded put falls back to no-cache: bytes still returned, next run re-downloads", async () => {
  class QuotaCache extends FakeCache {
    override async put(): Promise<void> {
      throw new DOMException("quota exceeded", "QuotaExceededError");
    }
  }
  class QuotaCacheStorage extends FakeCacheStorage {
    override async open(): Promise<CacheLike> {
      return new QuotaCache();
    }
  }
  const cs = new QuotaCacheStorage();
  let fetches = 0;
  const fetchFn = async (): Promise<Response> => {
    fetches++;
    return bytesResponse(4);
  };
  const { wasm, zkey } = await prefetchCircuitAssets("deposit", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn,
  });
  assert.equal(wasm.byteLength, 4, "the download still succeeds when the cache write fails");
  assert.equal(zkey.byteLength, 4);
  assert.equal(fetches, 2, "both assets were fetched despite the failed cache writes");
  // the un-cacheable state just re-downloads (banner returns) — never throws.
  await prefetchCircuitAssets("deposit", "/circuits", "88542b90", { cacheStorage: cs, fetchFn });
  assert.equal(fetches, 4, "no cache means the next prefetch re-downloads");
});

test("a broken Cache Storage (open throws) degrades to plain downloads", async () => {
  const cs: CacheStorageLike = {
    open: async () => {
      throw new Error("cache storage unavailable");
    },
    keys: async () => {
      throw new Error("cache storage unavailable");
    },
    delete: async () => false,
  };
  let fetches = 0;
  const { wasm } = await prefetchCircuitAssets("deposit", "/circuits", "88542b90", {
    cacheStorage: cs,
    fetchFn: async () => {
      fetches++;
      return bytesResponse(6);
    },
  });
  assert.equal(wasm.byteLength, 6, "proving assets still arrive with no cache at all");
  assert.equal(fetches, 2);
});
