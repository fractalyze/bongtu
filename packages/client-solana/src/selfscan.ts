// The self-scan feed adapter — how the UNCHANGED rail-agnostic discovery
// engine (@bongtu/client/selfscan) consumes the indexer's Solana backend.
//
// There is deliberately almost nothing here: the Solana backend feeds the SAME
// read model as the EVM one (apps/indexer/src/solana/ingest.ts — the routes
// cannot tell the backends apart, pinned by the indexer's Solana conformance
// leg), so the engine's SelfScanIo seam — events / nullifiers / head / path —
// is satisfied by the SAME typed client (@bongtu/core/indexerApi
// IndexerClient) that satisfies it on EVM, STRUCTURALLY, with no hand-built
// binding to drift. This module exists to make that wiring a named, typed
// fact: the declared return type IS the compile-time proof that the client
// still satisfies the seam, and the one place a Solana app binds its feed URL.
//
// What rides that feed on this rail (SOLR §3.2): op instruction data +
// self-CPI events + TreeState — viewTags, per-output kem cts, and slices in
// the identical wire shape, so viewTag prefilter -> Decaps -> leaf-match ->
// /path confirm all run byte-for-byte the same engine code.

import { IndexerClient, type IndexerClientOptions } from "@bongtu/core/indexerApi";
import type { SelfScanIo } from "@bongtu/client/selfscan";

/**
 * The four public reads one self-scan needs, bound to a Solana-backend
 * indexer. Hand the result straight to runSelfScan; it is a full
 * IndexerClient underneath, typed down to the seam the engine consumes.
 */
export function solanaSelfScanIo(indexerUrl: string, opts: IndexerClientOptions = {}): SelfScanIo {
  return new IndexerClient(indexerUrl, opts);
}
