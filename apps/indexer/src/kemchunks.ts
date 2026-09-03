// Consumer-disburse kem-ct chunk assembly (OPMOD §5, Option A-chunked).
//
// A consumer batch's 256 receiver kem ciphertexts do not fit one transaction
// (~330 KB vs the ~131 KB txpool byte cap), so they arrive in K permissionless
// chunk transactions keccak-bound to the batch tx's `kemChunkHashes`. The DATA
// is calldata-only (no event re-emit — the documented deviation from the
// logs-only rule), so ingest fetches each chunk tx via eth_getTransactionByHash
// and hands the decoded bytes here.
//
// Per batch this store tracks (K, expected hashes, per-chunk bytes) and derives:
//   - assembly: once all K chunks hold data, the concatenation splits into B
//     1088-byte per-output kem cts in leaf order — what the S3.6 scanner needs;
//   - status:  "complete" (all data present) / "pending" (chunks missing
//     on-chain, inside the grace window) / "withheld" (missing past it) /
//     "accepted-unassembled" (every chunk ACCEPTED on-chain — nothing was
//     withheld — but some chunk's bytes undecodable from its submit calldata;
//     boot re-attempts the fetch, ingest.ts refetchKemChunkData). All are
//     OPERATIONAL statuses distinct from the §4.4 disclosure alarms: nothing
//     on-chain-provable was violated — the notes are hash-committed but
//     undiscoverable-by-scan until the bytes land (funds intact, the §3.3
//     sender-self-sabotage class).
//   - the pending-module set the registry's watch-set rule needs: a REMOVED
//     disburse module must stay watched until every batch of its has all
//     chunks ACCEPTED on-chain (OPMOD §4.4 obligation 2).
//
// Storage discipline: chain-derived write-behind, flushed inside ingest's ONE
// persist transaction (postgres.ts), read model rebuilt by boot().

import { keccak256, type Hex } from "viem";
import type { Pool, PoolClient } from "pg";

const KEM_CT_BYTES = 1088;

/** One tracked batch. `chunks[j]` is the 0x-hex chunk data once its
 *  DisburseKemChunkAccepted was ingested — or null while unaccepted, AND for
 *  an accepted chunk whose tx calldata could not be decoded (a wrapped
 *  submission): `acceptedOnChain[j]` is the chain's fact, `chunks[j]` ours. */
export interface KemBatch {
  batchId: number; // == startLeafIndex, unique forever (append-only tree)
  module: string; // lowercase module address (the chunk watch-set key)
  txHash: string; // the batch tx
  chunkHashes: string[]; // 0x-hex keccak256 commitments, length K
  batchTimestamp: number; // unix seconds of the batch block (grace anchor)
  outputs: number; // B — total per-output kem cts the chunks carry
  chunks: (string | null)[];
  acceptedOnChain: boolean[];
  /** per-chunk accepting submit-tx hash (null while unaccepted) — what boot
   *  re-fetches when an accepted chunk's bytes are missing. */
  chunkTxHashes: (string | null)[];
}

export type KemStatus = "complete" | "pending" | "withheld" | "accepted-unassembled";

/** The /events projection of a batch's kem transport state. */
export interface KemProjection {
  status: KemStatus;
  chunkCount: number;
  acceptedCount: number;
  /** per-output 1088-byte kem cts (0x-hex), leaf order — present only when
   *  every chunk's bytes are assembled. */
  kemCiphertexts?: string[];
}

const strip0x = (h: string): string => h.replace(/^0x/i, "");

export class KemChunkStore {
  private readonly batches = new Map<number, KemBatch>();
  // (txHash:logIndex) replay dedup, same rationale as every chain-derived module.
  private readonly seen = new Set<string>();
  private pendingBatchRows: KemBatch[] = [];
  private pendingChunkRows: { batchId: number; chunkIndex: number; data: string | null; txHash: string | null }[] = [];

  constructor(private readonly pool: Pool | null = null) {}

  /** Load every persisted batch + chunk row (boot-time; idempotent). */
  async boot(): Promise<void> {
    if (!this.pool) return;
    const b = await this.pool.query(
      "SELECT batch_id, module, tx_hash, chunk_hashes, batch_timestamp, outputs FROM kem_batches",
    );
    for (const r of b.rows) {
      const hashes = JSON.parse(r.chunk_hashes as string) as string[];
      this.batches.set(Number(r.batch_id), {
        batchId: Number(r.batch_id),
        module: (r.module as string).toLowerCase(),
        txHash: r.tx_hash as string,
        chunkHashes: hashes,
        batchTimestamp: Number(r.batch_timestamp),
        outputs: Number(r.outputs),
        chunks: new Array(hashes.length).fill(null),
        acceptedOnChain: new Array(hashes.length).fill(false),
        chunkTxHashes: new Array(hashes.length).fill(null),
      });
    }
    const c = await this.pool.query("SELECT batch_id, chunk_index, data, tx_hash FROM kem_chunks");
    for (const r of c.rows) {
      const batch = this.batches.get(Number(r.batch_id));
      if (!batch) continue;
      batch.acceptedOnChain[Number(r.chunk_index)] = true;
      batch.chunks[Number(r.chunk_index)] = (r.data as string | null) ?? null;
      batch.chunkTxHashes[Number(r.chunk_index)] = (r.tx_hash as string | null) ?? null;
    }
  }

  /** Record a batch off its DisbursedPriv event (replay-deduped by batchId —
   *  the tree is append-only, so a batchId is minted exactly once). */
  recordBatch(args: {
    batchId: number;
    module: string;
    txHash: string;
    logIndex: number;
    chunkHashes: string[];
    batchTimestamp: number;
    outputs: number;
  }): void {
    const key = `${args.txHash}:${args.logIndex}`;
    if (this.seen.has(key) || this.batches.has(args.batchId)) return;
    this.seen.add(key);
    const batch: KemBatch = {
      batchId: args.batchId,
      module: args.module.toLowerCase(),
      txHash: args.txHash,
      chunkHashes: args.chunkHashes.map((h) => h.toLowerCase()),
      batchTimestamp: args.batchTimestamp,
      outputs: args.outputs,
      chunks: new Array(args.chunkHashes.length).fill(null),
      acceptedOnChain: new Array(args.chunkHashes.length).fill(false),
      chunkTxHashes: new Array(args.chunkHashes.length).fill(null),
    };
    this.batches.set(args.batchId, batch);
    this.pendingBatchRows.push(batch);
  }

  /**
   * Apply one DisburseKemChunkAccepted. `dataHex` is the chunk tx's decoded
   * calldata bytes — null when the submission was wrapped in a way the direct
   * decodeFunctionData cannot open (the batch then reads accepted-unassembled
   * once every accept lands; the chain's accept still counts toward the
   * watch-set drop rule). A decoded chunk is keccak-rechecked against the
   * batch-time commitment (mirror-invariant style — the chain already enforced
   * it, so a mismatch means the FETCHED calldata lied: throw, retry the range).
   *
   * Module-EMITTED inconsistencies (an accept for a batch we never recorded,
   * an out-of-range chunk index, a duplicate accept from a fresh tx) DEGRADE
   * instead: warn and drop the log, so the missing chunk simply keeps counting
   * toward pending/withheld. Modules are permissionlessly deployable code — a
   * throw here would wedge the whole poll loop forever on one hostile/buggy
   * emission, converting a discovery-transport defect into full availability
   * loss for every op family.
   */
  acceptChunk(args: { batchId: number; chunkIndex: number; dataHex: string | null; txHash: string; logIndex: number }): void {
    const key = `${args.txHash}:${args.logIndex}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const batch = this.batches.get(args.batchId);
    if (!batch) {
      console.warn(`kem chunk accept for UNKNOWN batch ${args.batchId} (tx ${args.txHash}) — module-emitted inconsistency, dropped`);
      return;
    }
    if (args.chunkIndex < 0 || args.chunkIndex >= batch.chunkHashes.length) {
      console.warn(`kem chunk index ${args.chunkIndex} out of range for batch ${args.batchId} (K=${batch.chunkHashes.length}, tx ${args.txHash}) — module-emitted inconsistency, dropped`);
      return;
    }
    if (batch.acceptedOnChain[args.chunkIndex]) {
      // A same-log replay was deduped above, so a second accept for the same
      // index is a fresh tx the shipped module contract would have reverted.
      console.warn(`duplicate kem chunk accept for batch ${args.batchId} chunk ${args.chunkIndex} (tx ${args.txHash}) — module-emitted inconsistency, dropped`);
      return;
    }
    if (args.dataHex !== null && keccak256(args.dataHex as Hex).toLowerCase() !== batch.chunkHashes[args.chunkIndex]) {
      throw new Error(`KemChunkStore: chunk ${args.chunkIndex} of batch ${args.batchId} keccak != committed hash — the chain enforced this, so the fetched calldata is corrupt`);
    }
    batch.acceptedOnChain[args.chunkIndex] = true;
    batch.chunks[args.chunkIndex] = args.dataHex;
    batch.chunkTxHashes[args.chunkIndex] = args.txHash;
    this.pendingChunkRows.push({ batchId: args.batchId, chunkIndex: args.chunkIndex, data: args.dataHex, txHash: args.txHash });
  }

  /**
   * Fill in the bytes of an already-ACCEPTED chunk whose data was missing —
   * the boot-time re-fetch path (accepted-unassembled recovery). No-ops unless
   * the chunk is accepted and still byteless; a keccak mismatch throws (the
   * bytes come from FETCHED calldata the chain already enforced, so a mismatch
   * means the RPC lied).
   */
  attachChunkData(batchId: number, chunkIndex: number, dataHex: string): void {
    const batch = this.batches.get(batchId);
    if (!batch || !batch.acceptedOnChain[chunkIndex] || batch.chunks[chunkIndex] !== null) return;
    if (keccak256(dataHex as Hex).toLowerCase() !== batch.chunkHashes[chunkIndex]) {
      throw new Error(`KemChunkStore: re-fetched chunk ${chunkIndex} of batch ${batchId} keccak != committed hash — the chain enforced this, so the fetched calldata is corrupt`);
    }
    batch.chunks[chunkIndex] = dataHex;
    this.pendingChunkRows.push({ batchId, chunkIndex, data: dataHex, txHash: batch.chunkTxHashes[chunkIndex] });
  }

  /** Every accepted-on-chain chunk whose bytes are still missing, with the
   *  accepting tx to re-fetch (null on a pre-tx_hash row) — the boot re-attempt
   *  worklist. */
  unassembledAccepted(): { batchId: number; chunkIndex: number; txHash: string | null }[] {
    const out: { batchId: number; chunkIndex: number; txHash: string | null }[] = [];
    for (const batch of this.batches.values()) {
      for (const j of batch.chunks.keys()) {
        if (batch.acceptedOnChain[j] && batch.chunks[j] === null) {
          out.push({ batchId: batch.batchId, chunkIndex: j, txHash: batch.chunkTxHashes[j] });
        }
      }
    }
    return out;
  }

  batch(batchId: number): KemBatch | null {
    return this.batches.get(batchId) ?? null;
  }

  /** The per-output kem ct array (leaf order), assembled once every chunk's
   *  bytes are in hand: concatenate chunk 0..K-1 and split into `outputs`
   *  1088-byte entries — no per-chunk arity arithmetic to drift. */
  assembled(batchId: number): string[] | null {
    const batch = this.batches.get(batchId);
    if (!batch || batch.chunks.some((c) => c === null)) return null;
    const all = batch.chunks.map((c) => strip0x(c!)).join("");
    if (all.length !== batch.outputs * KEM_CT_BYTES * 2) {
      throw new Error(`KemChunkStore: assembled batch ${batchId} is ${all.length / 2} bytes, want ${batch.outputs * KEM_CT_BYTES}`);
    }
    return Array.from({ length: batch.outputs }, (_, i) =>
      "0x" + all.slice(i * KEM_CT_BYTES * 2, (i + 1) * KEM_CT_BYTES * 2),
    );
  }

  /** kem transport status (OPMOD §5) — operational, never an alarm. Chunks
   *  missing ON-CHAIN read "pending" inside the grace window and "withheld"
   *  past it. Every chunk accepted (keccak-enforced) but some bytes missing
   *  reads "accepted-unassembled" — a distinct class: nothing was withheld,
   *  the bytes are on-chain, and boot re-attempts the fetch+decode. */
  status(batchId: number, nowSeconds: number, graceSeconds: number): KemStatus {
    const batch = this.batches.get(batchId);
    if (!batch) throw new Error(`KemChunkStore.status: unknown batch ${batchId}`);
    if (batch.chunks.every((c) => c !== null)) return "complete";
    if (batch.acceptedOnChain.every(Boolean)) return "accepted-unassembled";
    return nowSeconds - batch.batchTimestamp > graceSeconds ? "withheld" : "pending";
  }

  /** The /events projection for one batch (null when the batch is unknown —
   *  e.g. an entry replayed from a feed this store never tracked). */
  projection(batchId: number, nowSeconds: number, graceSeconds: number): KemProjection | null {
    const batch = this.batches.get(batchId);
    if (!batch) return null;
    const assembled = this.assembled(batchId);
    return {
      status: this.status(batchId, nowSeconds, graceSeconds),
      chunkCount: batch.chunkHashes.length,
      acceptedCount: batch.acceptedOnChain.filter(Boolean).length,
      ...(assembled ? { kemCiphertexts: assembled } : {}),
    };
  }

  /** Lowercase module addresses still owed chunk ACCEPTS on-chain — the
   *  registry's removed-module watch rule keys on this (an address may be
   *  dropped from the filter only once every batch of its has all chunks
   *  accepted, OPMOD §4.4). */
  pendingModules(): Set<string> {
    const out = new Set<string>();
    for (const batch of this.batches.values()) {
      if (batch.acceptedOnChain.some((a) => !a)) out.add(batch.module);
    }
    return out;
  }

  /** Stage buffered batch + chunk rows into the ingest's open txn
   *  (postgres.ts discipline: no BEGIN/COMMIT, no buffer clearing here). */
  async flushInto(client: PoolClient): Promise<void> {
    for (const b of this.pendingBatchRows) {
      await client.query(
        `INSERT INTO kem_batches (batch_id, module, tx_hash, chunk_hashes, batch_timestamp, outputs)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (batch_id) DO NOTHING`,
        [b.batchId, b.module, b.txHash, JSON.stringify(b.chunkHashes), b.batchTimestamp, b.outputs],
      );
    }
    for (const c of this.pendingChunkRows) {
      // COALESCE on conflict: a re-fetch that recovered the bytes upgrades the
      // NULL-data row it accepted with; nothing ever downgrades data to NULL.
      await client.query(
        `INSERT INTO kem_chunks (batch_id, chunk_index, data, tx_hash) VALUES ($1, $2, $3, $4)
         ON CONFLICT (batch_id, chunk_index) DO UPDATE
           SET data = COALESCE(EXCLUDED.data, kem_chunks.data),
               tx_hash = COALESCE(EXCLUDED.tx_hash, kem_chunks.tx_hash)`,
        [c.batchId, c.chunkIndex, c.data, c.txHash],
      );
    }
  }

  /** Drop the write-behind buffers AFTER the indexer's COMMIT (never before). */
  commitFlush(): void {
    this.pendingBatchRows = [];
    this.pendingChunkRows = [];
  }
}
