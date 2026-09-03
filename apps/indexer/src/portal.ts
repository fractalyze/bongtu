// Portal-deposit issuance records: the announcements the RESOLVER writes at
// POST /pay/{name} time (Slice ⑤ — a CEX sender can never announce, so
// issuance-time recording is what makes plain transfers workable) plus the
// swept/unswept state the factory's Swept event flips.
//
// Every field here is PUBLIC data: the announcement half (ephemeralPub, viewTag)
// is exactly what a withdraw announcement publishes on-chain, and the
// attribution half (name, owner) is the public name directory record the
// issuance resolved. There is nothing arbiter-gated in this module.
//
// Storage follows BOTH house disciplines, split by who writes:
//   - ISSUANCE is an API write like a name registration (names.ts): write-through
//     to Postgres FIRST, in-memory map updated only after the row commits, so
//     served state is never ahead of durable state.
//   - SWEPT-MARKING is chain-derived like every store/ledger row (postgres.ts):
//     applied to the read model immediately, SQL staged in a write-behind buffer
//     that ingest flushes inside its ONE persist transaction — the mark lands
//     atomically with the block cursor, so a crash can never leave a durable
//     "swept" ahead of the resume point (gap-only resume re-derives it).
//
// The salt rule (the ONE rule, restated from PortalFactory's header): the Swept
// event's `salt` IS portalSalt(stealthAddr) — the 20-byte stealth address
// left-padded to bytes32. Matching goes through core `portalSalt`, never a
// local re-pad.

import type { Pool, PoolClient } from "pg";
import type { PortalRecord } from "@bongtu/core/indexerApi";
import { portalSalt } from "@bongtu/core/stealth";

/** What the issuance route hands the registry (seq/createdAt/swept are ours). */
export type PortalIssuanceFields = Omit<
  PortalRecord,
  "kind" | "seq" | "createdAt" | "swept" | "sweptTxHash" | "sweptAmount"
>;

export class PortalRegistry {
  // Issuance order == seq order, so the array IS the cursor-paged feed.
  private readonly records: PortalRecord[] = [];
  // portalSalt(record.stealthAddr) -> record: the Swept-matching index.
  private readonly bySalt = new Map<string, PortalRecord>();
  // Write-behind buffer of swept-marks staged for the ingest transaction.
  private pendingSwept: PortalRecord[] = [];
  private seq = 0;

  constructor(private readonly pool: Pool | null = null) {}

  /** Load every persisted record (boot-time; idempotent). Seq order rebuilds the
   *  feed and continues the counter past the max persisted. */
  async boot(): Promise<void> {
    if (!this.pool) return;
    const res = await this.pool.query(
      `SELECT seq, name, owner, ephemeral_pub, view_tag, stealth_addr, destination,
              created_at, swept, swept_tx_hash, swept_amount
       FROM portal_announcements ORDER BY seq ASC`,
    );
    for (const r of res.rows) {
      this.index({
        kind: "portal",
        seq: Number(r.seq),
        name: r.name as string,
        owner: r.owner as string,
        ephemeralPub: r.ephemeral_pub as string,
        viewTag: Number(r.view_tag),
        stealthAddr: r.stealth_addr as string,
        destination: r.destination as string,
        createdAt: Number(r.created_at),
        swept: r.swept as boolean,
        sweptTxHash: (r.swept_tx_hash as string | null) ?? null,
        sweptAmount: (r.swept_amount as string | null) ?? null,
      });
    }
    this.seq = this.records.length > 0 ? this.records[this.records.length - 1].seq + 1 : 0;
  }

  private index(record: PortalRecord): void {
    this.records.push(record);
    this.bySalt.set(portalSalt(record.stealthAddr), record);
  }

  /**
   * Record one issuance (POST /pay/{name}). Write-through like a name
   * registration: the row commits before the map serves it. The stealth address
   * is stored lowercase so the salt index has one spelling.
   */
  async issue(fields: PortalIssuanceFields, nowSeconds: number): Promise<PortalRecord> {
    const record: PortalRecord = {
      kind: "portal",
      seq: this.seq,
      ...fields,
      stealthAddr: fields.stealthAddr.toLowerCase(),
      createdAt: nowSeconds,
      swept: false,
      sweptTxHash: null,
      sweptAmount: null,
    };
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO portal_announcements
           (seq, name, owner, ephemeral_pub, view_tag, stealth_addr, destination,
            created_at, swept, swept_tx_hash, swept_amount)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, NULL, NULL)`,
        [record.seq, record.name, record.owner, record.ephemeralPub, record.viewTag,
         record.stealthAddr, record.destination, record.createdAt],
      );
    }
    this.seq++;
    this.index(record);
    return record;
  }

  /** The full portal feed with seq > cursor, capped (the recipient scan path). */
  list(cursor = -1, limit = Infinity): PortalRecord[] {
    return this.records.filter((r) => r.seq > cursor).slice(0, limit);
  }

  /** The bot's work feed: unswept records with seq > cursor, capped. */
  unswept(cursor = -1, limit = Infinity): PortalRecord[] {
    return this.records.filter((r) => !r.swept && r.seq > cursor).slice(0, limit);
  }

  /**
   * Flip the record matching a factory Swept(salt, …) log. Applied to the read
   * model NOW, staged for the ingest transaction (flushInto). No-ops — an
   * unknown salt (this indexer never issued that address; issuance rows are
   * indexer-local like names) or an already-swept record (replayed log range) —
   * keep replay idempotent without double-buffering.
   */
  markSwept(salt: string, txHash: string, amount: bigint): void {
    const record = this.bySalt.get(salt.toLowerCase());
    if (!record || record.swept) return;
    record.swept = true;
    record.sweptTxHash = txHash;
    record.sweptAmount = amount.toString();
    this.pendingSwept.push(record);
  }

  /** Stage the buffered swept-marks into the ingest's open txn (postgres.ts
   *  discipline: no BEGIN/COMMIT and no buffer clearing here). Idempotent
   *  UPDATEs, so a poll-retry re-staging the same mark is harmless. */
  async flushInto(client: PoolClient): Promise<void> {
    for (const r of this.pendingSwept) {
      await client.query(
        "UPDATE portal_announcements SET swept = TRUE, swept_tx_hash = $2, swept_amount = $3 WHERE seq = $1",
        [r.seq, r.sweptTxHash, r.sweptAmount],
      );
    }
  }

  /** Drop the write-behind buffer AFTER the indexer's COMMIT (never before). */
  commitFlush(): void {
    this.pendingSwept = [];
  }
}
