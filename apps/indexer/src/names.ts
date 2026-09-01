// Off-chain name directory: `name -> { owner bjj pubkey, stealth meta-address }`.
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

import type { Pool } from "pg";
import type { NameRecord } from "@bongtu/core/indexerApi";

// The name grammar (NAME_PATTERN + normalizeName) lives with the names
// wire-contract in @bongtu/core/indexerApi, so the wallet's pay-by-name form
// judges input with the SAME function this registry registers under.
// Re-exported here so the routes and tests keep their registry-module import.
export { normalizeName } from "@bongtu/core/indexerApi";

export type RegisterOutcome =
  | { ok: true; record: NameRecord }
  | { ok: false; taken: NameRecord };

/**
 * The registry: an in-memory map for reads, write-through to Postgres when a
 * pool is present (the runtime always has one; unit tests and the pre-boot
 * placeholder run with null). The map is updated only AFTER the row commits,
 * so served state is never ahead of durable state.
 */
export class NameRegistry {
  private readonly byName = new Map<string, NameRecord>();

  constructor(private readonly pool: Pool | null = null) {}

  /** Load every persisted record (boot-time; idempotent). */
  async boot(): Promise<void> {
    if (!this.pool) return;
    const res = await this.pool.query(
      "SELECT name, owner, view_pub, spend_pub, updated_at FROM names",
    );
    for (const r of res.rows) {
      this.byName.set(r.name as string, {
        name: r.name as string,
        owner: r.owner as string,
        viewPub: r.view_pub as string,
        spendPub: r.spend_pub as string,
        updatedAt: Number(r.updated_at),
      });
    }
  }

  resolve(name: string): NameRecord | null {
    return this.byName.get(name) ?? null;
  }

  /** Register or same-owner-update `name`. Signature auth is the route's job
   *  (routes/names.ts); this enforces only the ownership-transition rule. */
  async register(
    reg: Omit<NameRecord, "updatedAt">,
    nowSeconds: number,
  ): Promise<RegisterOutcome> {
    const existing = this.byName.get(reg.name);
    if (existing && existing.owner !== reg.owner) {
      return { ok: false, taken: existing };
    }
    const record: NameRecord = { ...reg, updatedAt: nowSeconds };
    if (this.pool) {
      await this.pool.query(
        `INSERT INTO names (name, owner, view_pub, spend_pub, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (name) DO UPDATE
           SET owner = $2, view_pub = $3, spend_pub = $4, updated_at = $5`,
        [record.name, record.owner, record.viewPub, record.spendPub, record.updatedAt],
      );
    }
    this.byName.set(record.name, record);
    return { ok: true, record };
  }
}
