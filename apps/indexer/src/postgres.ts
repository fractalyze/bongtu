// Postgres store + ledger (U-I2, Postgres-only since U-I4) — the indexer's ONE
// runtime storage backend.
//
// Design forced by the sync read surface: the API route handlers and the ingest
// pipeline are synchronous (store/ledger reads return plain arrays, apply()
// returns void), and the anvil-free unit suite drives them directly. So both
// classes keep an in-memory read model — served synchronously — and add
// durability as a write-behind: apply()/addEvent() buffer the derived rows,
// ingest flushes them to SQL, and boot() reconstructs the read model + the
// MirrorTree frontier from SQL on restart. Reads are therefore never a
// per-request round-trip; Postgres is the crash-durable cache that lets a restart
// RESUME from the block cursor instead of replaying the whole chain.
//
// The crypto is NOT here: PostgresLedger calls the shared pure `deriveOp`
// (src/ledger.ts) exactly once per op — this module only records/reads.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Pool, type PoolClient } from "pg";
import { InMemoryStore, type FeedEntry, type StorePort } from "./store.js";
import { MirrorTree } from "./tree.js";
import {
  deriveOp,
  logEnvelopeAlarm,
  makeHistoryItem,
  ownerKey,
  pushHistory,
  recordNote,
  type EnvelopeAlarm,
  type LedgerHistoryItem,
  type LedgerNote,
  type OpEnvelope,
} from "./ledger.js";

const HERE = dirname(fileURLToPath(import.meta.url));

/** Open a connection pool and apply the idempotent schema. Caller owns the pool. */
export async function connect(databaseUrl: string): Promise<Pool> {
  const pool = new Pool({ connectionString: databaseUrl });
  // An idle client that dies (Postgres restart, network drop) emits 'error' on the
  // pool; without a listener pg re-emits it as an uncaught exception that would kill
  // the whole indexer. Log + swallow: the pool evicts the dead client and the next
  // acquisition opens a fresh one.
  pool.on("error", (err: Error) => {
    console.error("postgres pool idle-client error (evicted, will reconnect):", err.message);
  });
  const schema = readFileSync(join(HERE, "schema.sql"), "utf8");
  await pool.query(schema); // multi-statement DDL over the simple-query protocol
  return pool;
}

// ---------------------------------------------------------------------------
// Store adapter: in-memory read model + write-behind persistence + boot rebuild.
// ---------------------------------------------------------------------------

export class PostgresStore implements StorePort {
  private readonly mem = new InMemoryStore(); // sync read model + seq + first-sight dedup
  private tree: MirrorTree | null = null; // set in boot(); source of the leaf snapshot
  private pendingEvents: FeedEntry[] = [];
  private pendingNullifiers: string[] = [];

  constructor(private readonly pool: Pool) {}

  get lastBlock(): number {
    return this.mem.lastBlock;
  }
  set lastBlock(v: number) {
    this.mem.lastBlock = v;
  }

  addEvent(e: Omit<FeedEntry, "seq">): FeedEntry | null {
    const entry = this.mem.addEvent(e); // null on a replayed (txHash, logIndex)
    if (entry) this.pendingEvents.push(entry);
    return entry;
  }

  events(cursor?: number, limit?: number): FeedEntry[] {
    return this.mem.events(cursor, limit);
  }

  allEvents(): FeedEntry[] {
    return this.mem.allEvents();
  }

  getAlarms() {
    return this.mem.getAlarms();
  }

  addNullifiers(nfs: bigint[]): void {
    // Buffer exactly what the read model newly accepted (nonzero + not already seen).
    const before = new Set(this.mem.nullifiers());
    this.mem.addNullifiers(nfs);
    for (const nf of this.mem.nullifiers()) if (!before.has(nf)) this.pendingNullifiers.push(nf);
  }

  nullifiers(): string[] {
    return this.mem.nullifiers();
  }

  /** Reconstruct the frontier + read model from SQL (schema already applied). */
  async boot(tree: MirrorTree): Promise<void> {
    this.tree = tree;

    // Frontier: replay the persisted leaf rows (single appends + batch attaches) in
    // leaf-index order so the rebuilt root + nextLeafIndex equal the on-chain values.
    const lv = await this.pool.query("SELECT leaf_index, commitment, batch_root FROM leaves ORDER BY leaf_index ASC");
    tree.rebuildFromLeaves(
      lv.rows.map((r) => ({
        leafIndex: Number(r.leaf_index),
        commitment: r.commitment === null ? null : BigInt(r.commitment),
        batchRoot: r.batch_root === null ? null : BigInt(r.batch_root),
      })),
    );

    // Feed + disclosure alarms + seq: replay events through the read model in seq
    // order (mem re-assigns the identical seq and re-derives the alarm feed).
    const ev = await this.pool.query("SELECT payload FROM events ORDER BY seq ASC");
    for (const row of ev.rows) {
      const payload = row.payload as FeedEntry;
      const rest: Omit<FeedEntry, "seq"> & { seq?: number } = { ...payload };
      delete rest.seq;
      this.mem.addEvent(rest); // NOT buffered — already durable
    }

    // Spent-nullifier set.
    const nf = await this.pool.query("SELECT nf FROM nullifiers");
    this.mem.addNullifiers(nf.rows.map((r) => BigInt(r.nf)));

    // Block cursor (single row).
    const cur = await this.pool.query("SELECT last_block FROM ingest_cursor WHERE id = 1");
    this.mem.lastBlock = cur.rows.length > 0 ? Number(cur.rows[0].last_block) : -1;
  }

  /**
   * Stage events + nullifiers + the DELTA leaf rows into the indexer's open txn.
   * No BEGIN/COMMIT and no buffer clearing here — the indexer wraps this, the
   * ledger's flushInto, and persistCursorInto in ONE transaction and clears the
   * buffers (via commitFlush) only after that COMMIT, so a rollback retries cleanly.
   */
  async flushInto(client: PoolClient): Promise<void> {
    for (const e of this.pendingEvents) {
      await client.query(
        `INSERT INTO events (seq, tx_hash, log_index, block_number, kind, disclosure, payload)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (tx_hash, log_index) DO NOTHING`,
        [e.seq, e.txHash, e.logIndex, e.blockNumber, e.kind, e.disclosure?.status ?? null, JSON.stringify(e)],
      );
    }
    for (const nf of this.pendingNullifiers) {
      await client.query("INSERT INTO nullifiers (nf) VALUES ($1) ON CONFLICT (nf) DO NOTHING", [nf]);
    }
    // Delta: only the leaves recorded since the last flush (the tree buffers them
    // first-sight). Leaves are immutable, so ON CONFLICT DO NOTHING is the belt
    // against a poll-retry re-staging the same row.
    if (this.tree) {
      for (const r of this.tree.snapshotPendingLeaves()) {
        await client.query(
          `INSERT INTO leaves (leaf_index, commitment, batch_root) VALUES ($1, $2, $3)
           ON CONFLICT (leaf_index) DO NOTHING`,
          [r.leafIndex, r.commitment === null ? null : r.commitment.toString(), r.batchRoot === null ? null : r.batchRoot.toString()],
        );
      }
    }
  }

  /** Stage the cursor advance into the SAME txn as flushInto (never its own txn). */
  async persistCursorInto(client: PoolClient, block: number): Promise<void> {
    await client.query(
      `INSERT INTO ingest_cursor (id, last_block) VALUES (1, $1)
       ON CONFLICT (id) DO UPDATE SET last_block = EXCLUDED.last_block`,
      [block],
    );
  }

  /** Drop the write-behind buffers AFTER the indexer's COMMIT (incl. the tree delta). */
  commitFlush(): void {
    this.pendingEvents = [];
    this.pendingNullifiers = [];
    this.tree?.clearPendingLeaves();
  }
}

// ---------------------------------------------------------------------------
// Ledger adapter: shared deriveOp + in-memory read model + write-behind + rebuild.
// ---------------------------------------------------------------------------

export class PostgresLedger {
  private readonly byOwner = new Map<string, LedgerNote[]>();
  private readonly byCommitment = new Map<string, LedgerNote>();
  private readonly historyByOwner = new Map<string, LedgerHistoryItem[]>();
  private readonly alarms: EnvelopeAlarm[] = [];
  private readonly applied = new Set<string>();
  private historySeq = 0;

  private pendingNotes: LedgerNote[] = [];
  private pendingSpent: string[] = [];
  private pendingHistory: { owner: string; item: LedgerHistoryItem }[] = [];
  private pendingAlarms: EnvelopeAlarm[] = [];
  private pendingApplied: Array<[string, number]> = [];

  constructor(
    private readonly pool: Pool,
    private readonly arbiterPriv: bigint, // NEVER leaves this object
    // ML-KEM-768 decapsulation key (AUTHORITY_KEM_KEY) — same handling rule as
    // arbiterPriv: never logged, never serialized. null on a pre-KEM deploy
    // (the kem boot guard refuses V2 chains without it).
    private readonly kemSecret: Uint8Array | null,
    private readonly B: number,
    private readonly tree: MirrorTree,
  ) {}

  /** Ingest one op's envelope in chain order (idempotent on (txHash, logIndex)). */
  apply(op: OpEnvelope): void {
    const key = `${op.txHash}:${op.logIndex}`;
    if (this.applied.has(key)) return; // replayed op — already recorded
    this.applied.add(key);
    this.pendingApplied.push([op.txHash, op.logIndex]);

    const d = deriveOp(this.arbiterPriv, this.kemSecret, this.B, this.tree.H, op);
    for (const o of d.outputs) this.pendingNotes.push(recordNote(this.byOwner, this.byCommitment, o, op.txHash));
    for (const a of d.alarms) {
      this.alarms.push(a);
      this.pendingAlarms.push(a);
      logEnvelopeAlarm(a);
    }
    if (d.batchFill) this.tree.fillBatch(d.batchFill.start, d.batchFill.leaves);
    for (const c of d.spent) {
      const note = this.byCommitment.get(c.toString());
      if (note) {
        note.spent = true;
        this.pendingSpent.push(note.commitment);
      }
    }
    for (const h of d.history) {
      const item = makeHistoryItem(h, op, this.historySeq++);
      pushHistory(this.historyByOwner, h.owner, item);
      this.pendingHistory.push({ owner: ownerKey(h.owner[0], h.owner[1]), item });
    }
  }

  /** Every note owned by (x,y) — the arbiter's authoritative view of that owner. */
  notesOf(ownerX: bigint, ownerY: bigint): LedgerNote[] {
    return this.byOwner.get(ownerKey(ownerX, ownerY)) ?? [];
  }

  /** One owner's activity history, newest-first (seq desc). */
  historyOf(ownerX: bigint, ownerY: bigint): LedgerHistoryItem[] {
    const arr = this.historyByOwner.get(ownerKey(ownerX, ownerY)) ?? [];
    return [...arr].sort((a, b) => b.seq - a.seq);
  }

  /** Envelope cross-check failures surfaced during ingest (auditor-console feed). */
  getEnvelopeAlarms(): EnvelopeAlarm[] {
    return this.alarms;
  }

  /** Rebuild the note ledger read model from SQL — no re-decrypt of any envelope. */
  async boot(): Promise<void> {
    // Notes → byOwner / byCommitment, and re-fill each disburse batch so arbiter
    // /path serves within-batch leaves again.
    const nres = await this.pool.query(
      "SELECT owner_key, value, salt, commitment, leaf_index, tx_hash, spent FROM notes ORDER BY leaf_index ASC",
    );
    const batchLeaves = new Map<number, Array<{ leafIndex: number; commitment: bigint }>>();
    for (const r of nres.rows) {
      const [ox, oy] = (r.owner_key as string).split(",");
      const note: LedgerNote = {
        owner: [ox, oy],
        value: r.value,
        salt: r.salt,
        leafIndex: Number(r.leaf_index),
        commitment: r.commitment,
        txHash: r.tx_hash,
        spent: r.spent,
      };
      const k = ownerKey(BigInt(ox), BigInt(oy));
      const arr = this.byOwner.get(k) ?? [];
      arr.push(note);
      this.byOwner.set(k, arr);
      this.byCommitment.set(note.commitment, note);
      const block = Math.floor(note.leafIndex / this.B);
      if (this.tree.isBatch(block)) {
        const g = batchLeaves.get(block) ?? [];
        g.push({ leafIndex: note.leafIndex, commitment: BigInt(note.commitment) });
        batchLeaves.set(block, g);
      }
    }
    for (const [block, g] of batchLeaves) {
      if (g.length === this.B) {
        g.sort((a, b) => a.leafIndex - b.leafIndex);
        this.tree.fillBatch(block * this.B, g.map((x) => x.commitment));
      }
    }

    // History → historyByOwner; the next seq continues past the max persisted.
    const hres = await this.pool.query(
      "SELECT owner_key, kind, counterparty, amount, tx_hash, block_timestamp, seq FROM history ORDER BY seq ASC",
    );
    let maxSeq = -1;
    for (const r of hres.rows) {
      const item: LedgerHistoryItem = {
        kind: r.kind,
        counterparty: r.counterparty,
        amount: r.amount,
        txHash: r.tx_hash,
        blockTimestamp: Number(r.block_timestamp),
        seq: Number(r.seq),
      };
      const [ox, oy] = (r.owner_key as string).split(",");
      pushHistory(this.historyByOwner, [BigInt(ox), BigInt(oy)], item);
      if (item.seq > maxSeq) maxSeq = item.seq;
    }
    this.historySeq = maxSeq + 1;

    // Envelope cross-check alarms.
    const ares = await this.pool.query(
      "SELECT kind, tx_hash, detail, recomputed, expected FROM envelope_alarms ORDER BY id ASC",
    );
    for (const r of ares.rows) {
      this.alarms.push({ kind: r.kind, txHash: r.tx_hash, detail: r.detail, recomputed: r.recomputed, expected: r.expected });
    }

    // Applied-op dedup set.
    const opres = await this.pool.query("SELECT tx_hash, log_index FROM applied_ops");
    for (const r of opres.rows) this.applied.add(`${r.tx_hash}:${Number(r.log_index)}`);
  }

  /**
   * Stage notes + spent-marks + history + alarms + applied-ops into the indexer's
   * open txn. Like PostgresStore.flushInto: no BEGIN/COMMIT and no buffer clearing
   * here — the indexer owns the transaction and calls commitFlush after COMMIT, so
   * the note ledger rows land atomically with the store rows and the block cursor.
   */
  async flushInto(client: PoolClient): Promise<void> {
    for (const n of this.pendingNotes) {
      await client.query(
        `INSERT INTO notes (leaf_index, owner_key, value, salt, commitment, tx_hash, spent)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (leaf_index) DO NOTHING`,
        [n.leafIndex, `${n.owner[0]},${n.owner[1]}`, n.value, n.salt, n.commitment, n.txHash, n.spent],
      );
    }
    for (const c of this.pendingSpent) {
      await client.query("UPDATE notes SET spent = TRUE WHERE commitment = $1", [c]);
    }
    for (const p of this.pendingHistory) {
      await client.query(
        `INSERT INTO history (seq, owner_key, kind, counterparty, amount, tx_hash, block_timestamp)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (seq) DO NOTHING`,
        [p.item.seq, p.owner, p.item.kind, p.item.counterparty, p.item.amount, p.item.txHash, p.item.blockTimestamp],
      );
    }
    for (const a of this.pendingAlarms) {
      // Natural-key idempotency, matching every sibling table: a re-derived alarm
      // (tx_hash + detail pin the leaf/batch position) collapses instead of adding
      // a duplicate BIGSERIAL row.
      await client.query(
        `INSERT INTO envelope_alarms (kind, tx_hash, detail, recomputed, expected)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tx_hash, detail) DO NOTHING`,
        [a.kind, a.txHash, a.detail, a.recomputed, a.expected],
      );
    }
    for (const [tx, li] of this.pendingApplied) {
      await client.query(
        "INSERT INTO applied_ops (tx_hash, log_index) VALUES ($1, $2) ON CONFLICT (tx_hash, log_index) DO NOTHING",
        [tx, li],
      );
    }
  }

  /** Drop the write-behind buffers AFTER the indexer's COMMIT (never before). */
  commitFlush(): void {
    this.pendingNotes = [];
    this.pendingSpent = [];
    this.pendingHistory = [];
    this.pendingAlarms = [];
    this.pendingApplied = [];
  }
}
