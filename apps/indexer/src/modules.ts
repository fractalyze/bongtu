// The op-module registry mirror (OPMOD §1.4/§4.4 U5 obligation 1).
//
// The pool keeps no enumerable module array on-chain — the registered set is
// recoverable from the ModuleRegistered/ModuleRemoved stream alone, and since
// the U4 review the pool reverts no-op transitions (ModuleAlreadyRegistered /
// ModuleNotRegistered), so that stream is a BALANCED add/remove log by
// construction. The mirror therefore treats a spurious double-add or a
// remove-of-unknown as ingest corruption (throw — the poll loop retries from
// the unadvanced cursor), never as a state to tolerate.
//
// The WATCH-SET is wider than the registered set (OPMOD §4.4 obligation 2):
// `submitDisburseKemChunk` never crosses the applyOp gate, so a REMOVED
// disburse module still accepts chunk submissions and emits
// DisburseKemChunkAccepted from its deregistered address. watchAddresses()
// therefore keeps a removed address in the getLogs filter for as long as the
// caller says it still owns a kem-incomplete batch (the KemChunkStore knows).
//
// Storage discipline: chain-derived like the store/ledger rows — applied to
// the read model immediately, staged in a write-behind buffer that ingest
// flushes inside its ONE persist transaction (postgres.ts), so registry state
// lands atomically with the block cursor.

import type { Pool, PoolClient } from "pg";

/** One mirrored module row: lowercase address + whether it is currently
 *  registered (false = seen ModuleRemoved after its ModuleRegistered). */
export interface ModuleRow {
  address: string; // lowercase 0x-hex
  registered: boolean;
}

export class ModuleRegistry {
  // lowercase address -> registered (every address ever seen keeps a row —
  // removal flips the flag; the row itself is what remembers a removed
  // disburse module might still owe chunk events).
  private readonly byAddress = new Map<string, boolean>();
  // (txHash:logIndex) replay dedup — the poll loop can re-apply a range after a
  // mid-ingest throw, and a replayed registry event must not trip the
  // balanced-stream assert.
  private readonly seen = new Set<string>();
  // Write-behind: addresses whose row changed since the last durable flush.
  private pendingUpserts: ModuleRow[] = [];

  constructor(private readonly pool: Pool | null = null) {}

  /** Load every persisted module row (boot-time; idempotent). */
  async boot(): Promise<void> {
    if (!this.pool) return;
    const res = await this.pool.query("SELECT address, registered FROM modules");
    for (const r of res.rows) this.byAddress.set((r.address as string).toLowerCase(), r.registered as boolean);
  }

  /** Apply one ModuleRegistered log (balanced-stream assert; replay-deduped). */
  applyRegistered(txHash: string, logIndex: number, module: string): void {
    const key = `${txHash}:${logIndex}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const addr = module.toLowerCase();
    if (this.byAddress.get(addr) === true) {
      throw new Error(`ModuleRegistry: double ModuleRegistered(${addr}) — the pool reverts no-op transitions, so this stream is corrupt`);
    }
    this.byAddress.set(addr, true);
    this.pendingUpserts.push({ address: addr, registered: true });
  }

  /** Apply one ModuleRemoved log (balanced-stream assert; replay-deduped). */
  applyRemoved(txHash: string, logIndex: number, module: string): void {
    const key = `${txHash}:${logIndex}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const addr = module.toLowerCase();
    if (this.byAddress.get(addr) !== true) {
      throw new Error(`ModuleRegistry: ModuleRemoved(${addr}) without a live registration — the pool reverts no-op transitions, so this stream is corrupt`);
    }
    this.byAddress.set(addr, false);
    this.pendingUpserts.push({ address: addr, registered: false });
  }

  /** Whether `address` is currently registered (may call applyOp). */
  isRegistered(address: string): boolean {
    return this.byAddress.get(address.toLowerCase()) === true;
  }

  /** Whether `address` has EVER been registered. The mirror-invariant check on
   *  OpApplied.module uses this rather than isRegistered: a replayed range can
   *  contain an op from a module the SAME range later removes, and registry
   *  events dedup on replay, so the registry already sits at its end state. */
  isKnown(address: string): boolean {
    return this.byAddress.has(address.toLowerCase());
  }

  /** Every address ever seen in the stream, with its current flag. */
  all(): ModuleRow[] {
    return [...this.byAddress.entries()].map(([address, registered]) => ({ address, registered }));
  }

  /**
   * The event WATCH-SET for module-emitted logs: every registered module, plus
   * every REMOVED module still named in `pendingKemModules` (lowercase
   * addresses of modules with a kem-incomplete batch) — those keep emitting
   * DisburseKemChunkAccepted after deregistration and may only be dropped once
   * every batch of theirs has all chunks accepted (OPMOD §4.4).
   */
  watchAddresses(pendingKemModules: ReadonlySet<string>): string[] {
    return [...this.byAddress.entries()]
      .filter(([addr, registered]) => registered || pendingKemModules.has(addr))
      .map(([addr]) => addr);
  }

  /** Stage the changed rows into the ingest's open txn (postgres.ts
   *  discipline: no BEGIN/COMMIT, no buffer clearing here). Upserts, so a
   *  poll-retry re-staging the same transition is harmless. */
  async flushInto(client: PoolClient): Promise<void> {
    for (const r of this.pendingUpserts) {
      await client.query(
        `INSERT INTO modules (address, registered) VALUES ($1, $2)
         ON CONFLICT (address) DO UPDATE SET registered = EXCLUDED.registered`,
        [r.address, r.registered],
      );
    }
  }

  /** Drop the write-behind buffer AFTER the indexer's COMMIT (never before). */
  commitFlush(): void {
    this.pendingUpserts = [];
  }
}
