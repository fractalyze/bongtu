// Storage for the indexer: the ordered event/ciphertext feed + the ingest cursor.
//
// InMemoryStore here is NOT a runtime backend (the indexer is Postgres-only,
// U-I4): it is the synchronous read model PostgresStore (src/postgres.ts) wraps
// — seq assignment, first-sight dedup, the feed/alarm/nullifier reads — and the
// pure double the anvil-free unit test drives at the applyLogs level.
//
// Scope: the feed + alarm channel + block cursor ONLY. The tree state (leaf
// values, batch subtree roots, the merkle-path builder) lives in `MirrorTree`
// (tree.ts) — the Store no longer mirrors any tree, so the two are not kept in
// sync by call-site discipline.
//
// NOTE (client-side-decrypt model, SPEC §7): the store holds ONLY public chain
// data — ciphertext bytes, commitments, roots, nullifiers. It never holds or
// derives any user private key. Trial-decrypt happens in the wallet.

import type { PoolClient } from "pg";
import type { DisclosureResult } from "./disclosure.js";

/** Kind of note-bearing pool operation a feed entry came from. Mirrors the wire
 *  vocabulary in @bongtu/core/indexerApi; `transfer10` and `transfer10x2` are
 *  the two 10-input transfer circuits (10 outputs, or payment + change). */
export type EventKind =
  | "deposit"
  | "transfer"
  | "transfer10"
  | "transfer10x2"
  | "disburse"
  | "withdraw";

/**
 * A contiguous run of ciphertext field elements inside a feed entry's
 * `ciphertext` array. `leafIndex` ties the slice to the tree leaf a wallet will
 * request a merkle path for after it trial-decrypts (null = the authority
 * envelope tail, which is not a tree leaf).
 */
export interface Slice {
  offset: number;
  elts: number;
  leafIndex: number | null;
}

/** One entry of the SPEC §6b `/events` ciphertext feed. */
export interface FeedEntry {
  seq: number; // monotonic cursor key
  txHash: string;
  blockNumber: number;
  logIndex: number;
  kind: EventKind;
  epoch: number | null;
  ecdhPublicKey: [string, string] | null; // decimal strings
  encryptionNonce: string | null; // decimal string
  slices: Slice[];
  ciphertext: string[]; // decimal strings; the bytes a wallet trial-decrypts
  disclosure?: DisclosureResult; // present for `disburse`
}

/**
 * The store surface the Indexer + API read. Two implementers remain by design:
 * PostgresStore (src/postgres.ts) — the ONLY runtime store — and InMemoryStore,
 * the read-model component PostgresStore wraps (also the unit-test double). The
 * durable hooks are optional because only PostgresStore has them.
 */
export interface StorePort {
  /** Highest fully-ingested block (exclusive cursor for incremental tails). */
  lastBlock: number;
  addEvent(e: Omit<FeedEntry, "seq">): FeedEntry | null;
  events(cursor?: number, limit?: number): FeedEntry[];
  allEvents(): FeedEntry[];
  getAlarms(): DisclosureResult[];
  addNullifiers(nfs: bigint[]): void;
  nullifiers(): string[];
  // ---- durable-backend hooks (Postgres only; the in-memory adapter omits them,
  // making persistence a no-op). The indexer wraps the store's flushInto + the
  // ledger's flushInto + persistCursorInto in ONE caller-owned transaction, so the
  // cursor advances to block H iff every derived row for blocks <= H is durable.
  /** Stage buffered event/nullifier/leaf rows into the caller's open txn. */
  flushInto?(client: PoolClient): Promise<void>;
  /** Stage the ingest cursor advance into the SAME txn as flushInto. */
  persistCursorInto?(client: PoolClient, block: number): Promise<void>;
  /** Drop the write-behind buffers AFTER the indexer's COMMIT (never before). */
  commitFlush?(): void;
}

export class InMemoryStore implements StorePort {
  private feed: FeedEntry[] = [];
  private alarms: DisclosureResult[] = [];
  // (txHash, logIndex) of every feed entry — a replayed log range (poll retry
  // after a mid-ingest throw) must not double-add entries.
  private seen = new Set<string>();
  // The spent nullifier set (PUBLIC chain data), collected from Transferred /
  // Withdrawn / Disbursed events. Deduped by value, so a replayed range is safe;
  // zero (padded/disabled) nullifiers are never added (the contract skips them).
  private nullifierSet = new Set<string>();
  private seq = 0;
  /** Highest fully-ingested block (exclusive cursor for incremental tails). */
  lastBlock = -1;

  /**
   * Append a feed entry, assigning it the next cursor sequence. Idempotent on
   * (txHash, logIndex): a replayed log is dropped. Any disclosure that did not
   * fully check out joins the alarm channel — "mismatch" is a proven tamper;
   * "unverifiable"/"withheld" are publication gaps the auditor must judge
   * (SPEC §6b surfaces every incomplete disclosure, not just proven tampers).
   */
  addEvent(e: Omit<FeedEntry, "seq">): FeedEntry | null {
    const key = `${e.txHash}:${e.logIndex}`;
    if (this.seen.has(key)) return null;
    this.seen.add(key);
    const entry: FeedEntry = { ...e, seq: this.seq++ };
    this.feed.push(entry);
    if (entry.disclosure && entry.disclosure.status !== "verified") {
      this.alarms.push(entry.disclosure);
    }
    return entry;
  }

  /** Feed entries with seq > cursor (cursor -1/undefined returns all), capped. */
  events(cursor = -1, limit = 1000): FeedEntry[] {
    return this.feed.filter((e) => e.seq > cursor).slice(0, limit);
  }

  allEvents(): FeedEntry[] {
    return this.feed;
  }

  getAlarms(): DisclosureResult[] {
    return this.alarms;
  }

  /** Add an op's nullifiers to the spent set (nonzero only; deduped by value). */
  addNullifiers(nfs: bigint[]): void {
    for (const nf of nfs) if (nf !== 0n) this.nullifierSet.add(nf.toString());
  }

  /** The spent nullifier set as decimal strings (GET /nullifiers). */
  nullifiers(): string[] {
    return [...this.nullifierSet];
  }
}
