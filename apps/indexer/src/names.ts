// Off-chain name directory: `name -> { owner bjj pubkey, stealth meta-address,
// optional consumer triple (noteViewPub, kemEk) }`.
//
// This is the one indexer-owned MUTABLE state: every other table mirrors chain
// events, but a name registration has no on-chain footprint by design — the
// mapping is availability-trusted only, because every record is accepted only
// under the owner's bjj signature over the full payload (routes/names.ts), so a
// tampering server can at worst withhold a name, never forge one. Payers check
// nothing beyond TLS today; a paranoid payer can demand the record's signature
// out of band since the signed tuple is reproducible from the record fields.
//
// Semantics: first-come per name; an existing name is updatable only by the
// SAME owner (key rotation / stealth-meta refresh), never transferable — a
// payroll directory needs stable name→person bindings more than a resale
// market. One owner may hold many names.
//
// Consumer triple (OPMOD §6.4): the note-layer (noteViewPub, kemEk) columns are
// writable ONLY through a v2-signed payload — a v1-signed write updates the
// three legacy fields and leaves them untouched, so a captured legacy
// registration replayed inside the auth window re-asserts only what it already
// bound and can never clobber a consumer triple the owner added in between.

import type { Pool } from "pg";
import type { NameRecord } from "@bongtu/core/indexerApi";
import type { NonParticipantPersistence } from "./persist.js";

// The name grammar (NAME_PATTERN + normalizeName) lives with the names
// wire-contract in @bongtu/core/indexerApi, so the wallet's pay-by-name form
// judges input with the SAME function this registry registers under.
// Re-exported here so the routes and tests keep their registry-module import.
export { normalizeName } from "@bongtu/core/indexerApi";

export type RegisterOutcome =
  | { ok: true; record: NameRecord }
  | { ok: false; taken: NameRecord };

/** What a v2-signed write does to the consumer columns: set both (rotation /
 *  first registration) or clear both (the owner signed the zero-sentinels).
 *  `undefined` at the register() call = a v1 write — columns untouched. */
export interface ConsumerTripleWrite {
  noteViewPub: string | null;
  kemEk: string | null;
}

/**
 * The registry: an in-memory map for reads, write-through to Postgres when a
 * pool is present (the runtime always has one; unit tests and the pre-boot
 * placeholder run with null). The map is updated only AFTER the row commits,
 * so served state is never ahead of durable state.
 */
export class NameRegistry {
  /** Declared NON-participant in the atomic ingest persist (persist.ts):
   *  registrations are owner-signed HTTP POSTs with no chain event behind
   *  them, so each write commits in its own transaction at accept time —
   *  nothing is ever pending for an ingest flush. */
  readonly persistence: NonParticipantPersistence = "write-through";
  private readonly byName = new Map<string, NameRecord>();

  constructor(private readonly pool: Pool | null = null) {}

  /** Load every persisted record (boot-time; idempotent). */
  async boot(): Promise<void> {
    if (!this.pool) return;
    const res = await this.pool.query(
      "SELECT name, owner, view_pub, spend_pub, note_view_pub, kem_ek, updated_at FROM names",
    );
    for (const r of res.rows) {
      this.byName.set(r.name as string, {
        name: r.name as string,
        owner: r.owner as string,
        viewPub: r.view_pub as string,
        spendPub: r.spend_pub as string,
        ...(r.note_view_pub ? { noteViewPub: r.note_view_pub as string } : {}),
        ...(r.kem_ek ? { kemEk: r.kem_ek as string } : {}),
        updatedAt: Number(r.updated_at),
      });
    }
  }

  resolve(name: string): NameRecord | null {
    return this.byName.get(name) ?? null;
  }

  /**
   * Register or same-owner-update `name`. Signature auth AND the v1/v2 form
   * selection are the route's job (routes/names.ts); this enforces only the
   * ownership-transition rule plus the §6.4 column-write rule: `consumer`
   * undefined = a v1 write (legacy fields only, consumer columns preserved);
   * set = a v2 write applying exactly the given pair (nulls clear).
   */
  async register(
    reg: Omit<NameRecord, "updatedAt" | "noteViewPub" | "kemEk">,
    nowSeconds: number,
    consumer?: ConsumerTripleWrite,
  ): Promise<RegisterOutcome> {
    const existing = this.byName.get(reg.name);
    if (existing && existing.owner !== reg.owner) {
      return { ok: false, taken: existing };
    }
    // v1 preserves whatever consumer pair the record already carries; v2
    // applies its pair verbatim (null = clear).
    const pair = consumer === undefined
      ? { noteViewPub: existing?.noteViewPub ?? null, kemEk: existing?.kemEk ?? null }
      : consumer;
    const record: NameRecord = {
      name: reg.name,
      owner: reg.owner,
      viewPub: reg.viewPub,
      spendPub: reg.spendPub,
      ...(pair.noteViewPub !== null ? { noteViewPub: pair.noteViewPub } : {}),
      ...(pair.kemEk !== null ? { kemEk: pair.kemEk } : {}),
      updatedAt: nowSeconds,
    };
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO names (name, owner, view_pub, spend_pub, note_view_pub, kem_ek, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (name) DO UPDATE
           SET owner = $2, view_pub = $3, spend_pub = $4, note_view_pub = $5, kem_ek = $6, updated_at = $7`,
        [record.name, record.owner, record.viewPub, record.spendPub, pair.noteViewPub, pair.kemEk, record.updatedAt],
      );
    }
    this.byName.set(record.name, record);
    return { ok: true, record };
  }
}
