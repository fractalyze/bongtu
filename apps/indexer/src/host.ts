// The read-model HOST (SPEC §6b serving surface): the exact interface the
// HTTP API consumes, plus the engine-neutral base both rail engines extend.
//
// Two consumers:
//   - api/router.ts types RouteContext.ix against `IndexerHost`, so routes can
//     reach only the read model, the config knobs, and the health counters —
//     never an engine's chain plumbing (viem client, EVM ABI, log scanners,
//     Solana wire decoders);
//   - the rail engines (ingest.ts EVM, solana/ingest.ts) extend
//     `IndexerHostBase`, which owns the shared poll/health discipline and the
//     graceful close. Neither engine inherits the OTHER's machinery: the viem
//     client + Foundry ABI load live only in the EVM class, the signature
//     cursor only in the Solana class — a Solana-only boot touches no
//     chains/evm artifact and creates no viem client.
//
// Persistence participation is DECLARED, not inherited: each engine builds
// its ordered participant list at boot and hands it to the one
// `persistAtomically` implementation (persist.ts owns the lifecycle and the
// commit-only-after-COMMIT rule).

import type { Pool } from "pg";
import { BaseError } from "viem";

import type { ChainConfig } from "./chain.js";
import type { MirrorTree } from "./tree.js";
import { InMemoryStore, type StorePort } from "./store.js";
import type { PostgresLedger } from "./postgres.js";
import { NameRegistry } from "./names.js";
import { PortalRegistry } from "./portal.js";
import { KemChunkStore } from "./kemchunks.js";
import { DisclosureRegistry } from "./solana/served.js";

/**
 * What the API is allowed to see of an indexer: the read-model members the
 * routes actually consume, nothing engine-specific. Both rail engines
 * implement it via IndexerHostBase below.
 */
export interface IndexerHost {
  /** Boot-time config knobs; routes read at most cfg.portalFactory off it. */
  readonly cfg: ChainConfig;
  /** The feed/nullifier/alarm read model (PostgresStore after first ingest). */
  store: StorePort;
  /** The IMT mirror (undefined only before first ingest — /health guards). */
  tree: MirrorTree;
  /** The arbiter note ledger — null in public mode and pre-boot. */
  ledger: PostgresLedger | null;
  /** Institution-served disclosure blobs (GET /disclosure + alarm classes). */
  readonly disclosures: DisclosureRegistry;
  /** Consumer-disburse kem chunk assembly (the /events kem projection). */
  kem: KemChunkStore;
  /** The off-chain name directory (/names). */
  names: NameRegistry;
  /** Portal issuance records (/pay, /portal/*). */
  portal: PortalRegistry;
  /** Arbiter routing flag — gates the /notes + /history + /auth route set. */
  readonly arbiterMode: boolean;
  /** The pool's disburse batch arity B (0 before first ingest). */
  batchSize: number;
  /** kem-pending → kem-withheld grace window in seconds (OPMOD §5). */
  kemGraceSeconds: number;

  // ---- tail-poll operational state (projected by GET /health) --------------
  lastError: string | null;
  lastErrorAt: number | null; // ms epoch
  consecutiveFailures: number;
  lastSuccessAt: number | null; // ms epoch
  transientHeadRaces: number;
  lastTransientAt: number | null; // ms epoch

  /**
   * eth_call `PortalFactory.addressOf(salt)` — the issuance route's
   * destination lookup. An EVM-ONLY capability, hence optional: the Solana
   * engine does not provide it, and the portal route guards its absence with
   * the same 404 an unconfigured PORTAL_FACTORY produces.
   */
  portalAddressOf?(salt: string): Promise<string>;
}

/**
 * A tail poll racing the RPC's replicas, not a real failure: `getBlockNumber()`
 * was answered by a fresher replica than the `eth_getLogs` / pinned `eth_call`
 * that follows, so the pinned block is "beyond head" (or not yet visible) on the
 * laggier node — observed on the load-balanced public sepolia.base.org, whose
 * reported head regresses several blocks between consecutive requests. The
 * cursor stays unadvanced and the next poll re-derives a fresh head, so these
 * self-heal; counting them toward the /health failure streak would flip
 * ok:false during ordinary replica skew (2,175 hits in one 48h window).
 */
function isTransientHeadRaceError(e: unknown): boolean {
  const matches = (s: string) =>
    s.includes("block range extends beyond current head block") || s.includes("block not found");
  if (e instanceof BaseError) {
    return (
      e.walk((err) => {
        const details = (err as { details?: unknown }).details;
        return (typeof details === "string" && matches(details)) || (err instanceof Error && matches(err.message));
      }) !== null
    );
  }
  return e instanceof Error && matches(e.message);
}

/**
 * The engine-neutral half of an indexer: the read-model members the API host
 * interface promises, plus the poll/health discipline and the graceful close.
 * The constructor is PURE of I/O — no client construction, no artifact reads —
 * so a rail whose chain plumbing lives elsewhere (Solana) boots without EVM
 * artifacts on disk.
 */
export abstract class IndexerHostBase implements IndexerHost {
  readonly cfg: ChainConfig;
  // The runtime store is ALWAYS PostgresStore (Postgres-only, U-I4), swapped in
  // by the engine's boot at first ingest. The InMemoryStore default is the
  // pre-boot placeholder (so /health can answer before the first ingest
  // completes) and the pure applyLogs-level double the anvil-free unit test
  // drives — it is the same read-model class PostgresStore itself wraps, never
  // a selectable backend. Not `readonly` — boot replaces it in place, and the
  // API reads `ix.store` live per request.
  store: StorePort = new InMemoryStore();
  tree!: MirrorTree;
  batchSize = 0;
  // Arbiter mode (SPEC §6b v2): set when the config carries the arbiter private
  // key. The key lives only inside `ledger`; `arbiterMode` is the routing flag
  // the API uses to register /notes + serve within-batch paths. The key itself
  // is NEVER read back out for logging or HTTP.
  readonly arbiterPriv: bigint | null;
  readonly arbiterMode: boolean;
  ledger: PostgresLedger | null = null;
  // The name directory (names.ts) — always present so /names serves in every
  // mode; the engine's boot swaps in the pool-backed one (pre-boot: memory-only).
  names: NameRegistry = new NameRegistry(null);
  // Portal issuance records (portal.ts) — always present so the /portal routes
  // can answer in every mode; the EVM boot swaps in the pool-backed one. The
  // routes themselves 404 when cfg.portalFactory is unset.
  portal: PortalRegistry = new PortalRegistry(null);
  // Consumer-disburse kem chunk assembly (kemchunks.ts, OPMOD §5): batch
  // hashes + accepted chunk bytes, the /events kem projection, and the
  // pending-module set the removed-module watch rule keys on.
  kem: KemChunkStore = new KemChunkStore(null);
  // The kem-pending → kem-withheld grace window in seconds (OPMOD §5) — parsed
  // ONCE at boot (chain.ts KEM_GRACE_SECONDS); routes read it here, never
  // process.env. Mutable on purpose: the conformance test flips it mid-run to
  // project the same incomplete batch as withheld deterministically.
  kemGraceSeconds: number;
  // Institution-served disclosure blobs (SOLR §3.3.2): the registry behind
  // GET /disclosure and the served-blob alarm classes. Only the Solana
  // engine records batches into it — on EVM the disburse bytes are
  // consensus-published — so it stays empty there and every route it feeds
  // serves identical bytes across backends.
  readonly disclosures: DisclosureRegistry;
  // The shared Postgres pool (set by the engine's boot; null before first
  // ingest). Owned here so close() is shared; persist never reads it
  // implicitly — each engine hands it to persistAtomically explicitly along
  // with its declared participant list.
  protected pgPool: Pool | null = null;

  // ---- tail-poll operational state (projected by GET /health) --------------
  // Recorded by pollOnce so "wedged since block N" vs "healthy" is machine-
  // visible instead of a swallow-and-log line on a headless service.
  lastError: string | null = null;
  lastErrorAt: number | null = null; // ms epoch
  consecutiveFailures = 0;
  lastSuccessAt: number | null = null; // ms epoch
  // Head-race retries (see isTransientHeadRaceError) — observability only,
  // never part of the failure streak. lastSuccessAt is NOT stamped on a
  // transient, so a tail that only ever head-races still shows a stale
  // lastSuccessAt to callers.
  transientHeadRaces = 0;
  lastTransientAt: number | null = null; // ms epoch
  private polling = false; // one in-flight tail attempt at a time

  constructor(cfg: ChainConfig) {
    this.cfg = cfg;
    this.arbiterPriv = cfg.authorityKey ?? null;
    this.arbiterMode = this.arbiterPriv !== null;
    this.kemGraceSeconds = cfg.kemGraceSeconds ?? 3600;
    this.disclosures = new DisclosureRegistry(cfg.disclosureDir ?? null, cfg.disclosureGraceSeconds ?? 3600);
  }

  /** One replay pass from the engine's cursor (EVM: block range; Solana:
   *  signature gap — its implementation ignores the arguments). */
  abstract ingest(fromBlock?: number, toBlock?: number): Promise<void>;

  /** Live head state straight from the chain (the mirror is asserted against it). */
  abstract head(): Promise<{ root: bigint; nextLeafIndex: number }>;

  /** The KEM boot guard (pq-envelope-design.md §7) — returns the fatal
   *  one-liner or null; index.ts exits on it. */
  abstract kemBootGuard(): Promise<string | null>;

  /**
   * One guarded tail attempt: re-ingest from the cursor, recording success /
   * failure state for GET /health. Never throws — a failing RPC or a genuine
   * mirror-root divergence lands in `lastError` + `consecutiveFailures` instead
   * of only a log line, and the cursor stays unadvanced so the next attempt
   * retries the same range. Replica head-races are the one exception: they land
   * in `transientHeadRaces` and never touch the failure streak. Concurrent
   * calls coalesce (one in-flight attempt).
   */
  async pollOnce(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      await this.ingest(this.store.lastBlock + 1);
      this.consecutiveFailures = 0;
      this.lastSuccessAt = Date.now();
    } catch (e) {
      if (isTransientHeadRaceError(e)) {
        // Replica head-race: retried from the same cursor next poll. One short
        // line (not viem's multi-line dump), and no streak bump — see
        // isTransientHeadRaceError for why this must not reach /health's ok.
        this.transientHeadRaces++;
        this.lastTransientAt = Date.now();
        console.warn(`tail ingest head-race #${this.transientHeadRaces} (retrying next poll): ${(e as Error).message.split("\n", 1)[0]}`);
      } else {
        this.consecutiveFailures++;
        this.lastError = (e as Error).message;
        this.lastErrorAt = Date.now();
        console.error("tail ingest error:", this.lastError);
      }
    } finally {
      this.polling = false;
    }
  }

  /** Start the incremental tail poll (one pollOnce per `pollMs`); returns a stopper. */
  startTailPolling(pollMs: number): () => void {
    const timer = setInterval(() => {
      void this.pollOnce();
    }, pollMs);
    return () => clearInterval(timer);
  }

  /** Release the Postgres pool on a graceful shutdown (no-op before first ingest). */
  async close(): Promise<void> {
    if (this.pgPool) {
      await this.pgPool.end();
      this.pgPool = null;
    }
  }
}
