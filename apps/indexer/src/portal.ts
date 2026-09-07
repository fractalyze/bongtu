// Portal/receive announcement records: the rows the RESOLVER writes at
// POST /pay/{name} time (Slice ⑤ — a CEX sender can never announce, so
// issuance-time recording is what makes plain transfers workable), the rows the
// PAY PAGE writes at POST /portal/announce time (browser-side derivation), the
// rows a priv-factory `Announced` event BACKFILLS from chain data, plus the
// swept/unswept state either factory's Swept event flips.
//
// ATTRIBUTION SPLIT (the receive product's unlinkability surface): rows store
// the name-owner attribution because the SWEEP BOT needs it (which recipient's
// keys the deposit mints to), but only the operator-facing unswept feed serves
// it — every public projection goes through `toPublic`, which drops
// name/owner. The recipient does not need attribution: its view key re-derives
// which records are its own (scanStealthAnnouncement).
//
// Storage follows BOTH house disciplines, split by who writes:
//   - ISSUANCE/ANNOUNCE is an API write like a name registration (names.ts):
//     write-through to Postgres FIRST, in-memory map updated only after the row
//     commits, so served state is never ahead of durable state.
//   - SWEPT-MARKING and Announced-BACKFILL are chain-derived like every
//     store/ledger row (postgres.ts): applied to the read model immediately,
//     SQL staged in a write-behind buffer that ingest flushes inside its ONE
//     persist transaction — the write lands atomically with the block cursor,
//     so a crash can never leave durable chain-derived state ahead of the
//     resume point (gap-only resume re-derives it).
//
// The salt rule (the ONE rule, restated from PortalFactory's header): the Swept
// event's `salt` IS portalSalt(stealthAddr) — the 20-byte stealth address
// left-padded to bytes32. Matching goes through core `portalSalt`, never a
// local re-pad.

import type { Pool, PoolClient } from "pg";
import type { PortalPublicRecord, PortalRecord } from "@bongtu/core/indexerApi";
import { portalSalt } from "@bongtu/core/stealth";

/** What the issuance/announce routes hand the registry (seq/createdAt/swept are ours). */
export type PortalIssuanceFields = Omit<
  PortalRecord,
  "kind" | "seq" | "createdAt" | "swept" | "sweptTxHash" | "sweptAmount"
>;

/** The public projection: the attributed row minus name/owner. A dedicated
 *  function (not spread-with-delete) so "the public feed carries no
 *  attribution field AT ALL" stays a positive property the tests can pin. */
export function toPublic(r: PortalRecord): PortalPublicRecord {
  return {
    kind: r.kind,
    seq: r.seq,
    rail: r.rail,
    factory: r.factory,
    ephemeralPub: r.ephemeralPub,
    viewTag: r.viewTag,
    stealthAddr: r.stealthAddr,
    destination: r.destination,
    createdAt: r.createdAt,
    swept: r.swept,
    sweptTxHash: r.sweptTxHash,
    sweptAmount: r.sweptAmount,
  };
}

/** The first-write-wins refusal, typed so the announce route can answer 409
 *  (any other issue() failure stays the catch-all 500). */
export class DuplicateStealthAddressError extends Error {
  constructor(readonly stealthAddr: string) {
    super(`stealth address already recorded: ${stealthAddr}`);
  }
}

export class PortalRegistry {
  // Issuance order == seq order, so the array IS the cursor-paged feed.
  private readonly records: PortalRecord[] = [];
  // portalSalt(record.stealthAddr) -> record: the Swept/Announced-matching index.
  private readonly bySalt = new Map<string, PortalRecord>();
  // Write-behind buffers of chain-derived writes staged for the ingest transaction.
  private pendingSwept: PortalRecord[] = [];
  private pendingInserts: PortalRecord[] = [];
  private seq = 0;

  constructor(private readonly pool: Pool | null = null) {}

  /** Load every persisted record (boot-time; idempotent). Seq order rebuilds the
   *  feed and continues the counter past the max persisted. Rows from before the
   *  factory/rail columns default to the legacy portal flavor ("", "evm"). */
  async boot(): Promise<void> {
    if (!this.pool) return;
    const res = await this.pool.query(
      `SELECT seq, name, owner, ephemeral_pub, view_tag, stealth_addr, destination,
              factory, rail, created_at, swept, swept_tx_hash, swept_amount
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
        factory: (r.factory as string | null) ?? "",
        rail: (r.rail as string | null) ?? "evm",
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

  /** First-write-wins probe: is this stealth address already recorded? The
   *  announce route 409s on it — a hijacker re-announcing an observed
   *  destination under its own label always loses the race, because the honest
   *  record was written before the address was ever displayed. A probe alone
   *  cannot close a CONCURRENT double-announce (the route awaits the
   *  destination recompute in between): `issue` owns that, via the unique
   *  index (Postgres) and its own final pre-index recheck (memory mode). */
  hasStealth(stealthAddr: string): boolean {
    return this.bySalt.has(portalSalt(stealthAddr));
  }

  /**
   * Record one issuance (POST /pay/{name}) or announce (POST /portal/announce).
   * Write-through like a name registration: the row commits before the map
   * serves it. The stealth address is stored lowercase so the salt index has
   * one spelling.
   *
   * FIRST WRITE WINS is enforced HERE, atomically, not only by the route's
   * probe: two concurrent announces for one address both pass the probe (the
   * route awaits the destination recompute in between), so the database's
   * unique stealth_addr index makes exactly one INSERT land — the loser's
   * 23505 surfaces as DuplicateStealthAddressError (the route's 409). Memory
   * mode (unit tests) has no database, but also no await between the recheck
   * below and the index write, so the same recheck is race-free there.
   */
  async issue(fields: PortalIssuanceFields, nowSeconds: number): Promise<PortalRecord> {
    const record: PortalRecord = {
      kind: "portal",
      // Allocated EAGERLY (before any await) so two concurrent issues can
      // never share a seq; a failed insert leaves a gap, which the seq>cursor
      // feed paging is indifferent to.
      seq: this.seq++,
      ...fields,
      stealthAddr: fields.stealthAddr.toLowerCase(),
      createdAt: nowSeconds,
      swept: false,
      sweptTxHash: null,
      sweptAmount: null,
    };
    if (this.hasStealth(record.stealthAddr)) throw new DuplicateStealthAddressError(record.stealthAddr);
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO portal_announcements
           (seq, name, owner, ephemeral_pub, view_tag, stealth_addr, destination,
            factory, rail, created_at, swept, swept_tx_hash, swept_amount)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, FALSE, NULL, NULL)`,
        [record.seq, record.name, record.owner, record.ephemeralPub, record.viewTag,
         record.stealthAddr, record.destination, record.factory, record.rail, record.createdAt],
      ).catch((e: unknown) => {
        // unique_violation on the stealth_addr index: the concurrent twin won
        // the insert. Re-thrown typed so the route can 409 instead of 500 —
        // and the in-memory map is NOT updated with the losing row. Matched by
        // constraint name: 23505 alone would also swallow a seq PK violation
        // (a different bug that must stay loud).
        const pg = e as { code?: string; constraint?: string };
        if (pg.code === "23505" && pg.constraint === "portal_stealth_addr_uniq") {
          throw new DuplicateStealthAddressError(record.stealthAddr);
        }
        throw e;
      });
    }
    this.index(record);
    return record;
  }

  /** The full attributed feed with seq > cursor, capped (operator-side reads;
   *  public routes project through `toPublic`). */
  list(cursor = -1, limit = Infinity): PortalRecord[] {
    return this.records.filter((r) => r.seq > cursor).slice(0, limit);
  }

  /** The public announcement feed: `list` through the attribution-dropping
   *  projection (the recipient scan path). */
  listPublic(cursor = -1, limit = Infinity): PortalPublicRecord[] {
    return this.list(cursor, limit).map(toPublic);
  }

  /** The bot's work feed: unswept ATTRIBUTED records with seq > cursor, capped.
   *  Served only behind the operator token (routes/portal.ts). */
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

  /**
   * Ingest a priv-factory Announced(salt, ephemeralPub, viewTag) log — the
   * chain-only recovery path. A known salt is a no-op: the row was written at
   * announce time and the same tx's Swept already flipped it (validating chain
   * against store is the recipient's own scan's job, not a server overwrite).
   * An UNKNOWN salt is a lost/foreign announcement (this indexer never served
   * that issuance — a wiped store, or a record another operator issued):
   * backfill a row from the event so the feed serves it again. Chain data
   * carries no attribution, so the row's name/owner are empty — and it is
   * already swept (Announced only ever fires inside a sweep tx), so it never
   * enters the bot's work feed.
   */
  recordChainAnnouncement(fields: {
    salt: string;
    ephemeralPub: string;
    viewTag: number;
    destination: string;
    factory: string;
    txHash: string;
    amount: bigint;
    blockTimestamp: number;
  }): void {
    const salt = fields.salt.toLowerCase();
    if (this.bySalt.has(salt)) return;
    const record: PortalRecord = {
      kind: "portal",
      seq: this.seq,
      name: "",
      owner: "",
      ephemeralPub: fields.ephemeralPub,
      viewTag: fields.viewTag,
      // the salt IS the left-padded stealth address (the one rule) — unpad.
      stealthAddr: "0x" + salt.slice(-40),
      destination: fields.destination,
      factory: fields.factory,
      rail: "evm",
      createdAt: fields.blockTimestamp,
      swept: true,
      sweptTxHash: fields.txHash,
      sweptAmount: fields.amount.toString(),
    };
    this.seq++;
    this.records.push(record);
    this.bySalt.set(salt, record);
    this.pendingInserts.push(record);
  }

  /** Stage the buffered chain-derived writes into the ingest's open txn
   *  (postgres.ts discipline: no BEGIN/COMMIT and no buffer clearing here).
   *  Idempotent statements, so a poll-retry re-staging is harmless. */
  async flushInto(client: PoolClient): Promise<void> {
    for (const r of this.pendingInserts) {
      // TARGETLESS on-conflict: a backfill row can collide on seq (replayed
      // range) OR on the unique stealth_addr (an announce that committed
      // between the miss and this flush). Naming only (seq) would let the
      // address conflict abort the whole persist transaction — and since the
      // buffer clears only after COMMIT, every retry would re-conflict and
      // wedge ingest until restart.
      await client.query(
        `INSERT INTO portal_announcements
           (seq, name, owner, ephemeral_pub, view_tag, stealth_addr, destination,
            factory, rail, created_at, swept, swept_tx_hash, swept_amount)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT DO NOTHING`,
        [r.seq, r.name, r.owner, r.ephemeralPub, r.viewTag, r.stealthAddr, r.destination,
         r.factory, r.rail, r.createdAt, r.swept, r.sweptTxHash, r.sweptAmount],
      );
    }
    for (const r of this.pendingSwept) {
      await client.query(
        "UPDATE portal_announcements SET swept = TRUE, swept_tx_hash = $2, swept_amount = $3 WHERE seq = $1",
        [r.seq, r.sweptTxHash, r.sweptAmount],
      );
    }
  }

  /** Drop the write-behind buffers AFTER the indexer's COMMIT (never before). */
  commitFlush(): void {
    this.pendingSwept = [];
    this.pendingInserts = [];
  }
}
