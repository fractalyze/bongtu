// Storage for the indexer: the ordered event/ciphertext feed + the ingest cursor.
//
// In-memory only, re-derived from chain on every start. That is sufficient for
// the PoC (SPEC §6b: the indexer is a convenience/availability layer, not
// trust-critical for funds) and keeps chain the single source of truth.
//
// Scope: the feed + alarm channel + block cursor ONLY. The tree state (leaf
// values, batch subtree roots, the merkle-path builder) lives in `MirrorTree`
// (tree.ts) — the Store no longer mirrors any tree, so the two are not kept in
// sync by call-site discipline.
//
// NOTE (client-side-decrypt model, SPEC §7): the store holds ONLY public chain
// data — ciphertext bytes, commitments, roots, nullifiers. It never holds or
// derives any user private key. Trial-decrypt happens in the wallet.

import type { DisclosureResult } from "./disclosure.js";

/** Kind of note-bearing pool operation a feed entry came from. */
export type EventKind = "deposit" | "transfer" | "disburse" | "withdraw";

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

export class Store {
  private feed: FeedEntry[] = [];
  private alarms: DisclosureResult[] = [];
  // (txHash, logIndex) of every feed entry — a replayed log range (poll retry
  // after a mid-ingest throw) must not double-add entries.
  private seen = new Set<string>();
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
}
