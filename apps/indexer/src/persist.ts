// Declared-participant persistence — the ONE atomic write-behind transaction.
//
// Six objects follow the same write-behind lifecycle:
//   boot()        rebuild the read model from SQL (signatures vary per
//                 participant — PostgresStore takes the MirrorTree whose
//                 pending leaves it snapshots; the rest take nothing);
//   flushInto()   stage the pending buffers into the CALLER's open
//                 transaction (no BEGIN/COMMIT of their own);
//   commitFlush() drop the write-behind buffers / advance in-memory cursors.
//
// `persistAtomically` below is the single implementation of the transaction.
// Each rail hands it its DECLARED ordered participant list (built at boot):
//   EVM    — store, ledger (arbiter mode), portal, modules, kem, block cursor;
//   Solana — store, block cursor, signature cursor.
// The cursor writes are participants themselves (BlockCursor here, the
// signature cursor in solana/ingest.ts), staged LAST so every row for
// position H is in the transaction before the cursor that claims H — a crash
// can never leave rows ahead of the cursor.
//
// THE RULE, stated once: commitFlush runs ONLY after COMMIT returned. A throw
// anywhere before that (a participant's flushInto, the fault hook, COMMIT
// itself) ROLLs BACK the whole transaction and leaves every buffer and the
// in-memory cursor untouched, so the next poll retries the same range
// verbatim (every participant is replay-idempotent).
//
// Deliberate NON-participants (named, not silent):
//   - NameRegistry (names.ts) is WRITE-THROUGH: a name registration is an
//     owner-signed HTTP POST with no chain event behind it, so each write is
//     its own transaction at accept time and there is never a pending buffer
//     to stage — see the `persistence` marker on the class.
//   - DisclosureRegistry (solana/served.ts) REBUILDS AT BOOT from the
//     persisted disburse anchors + the operator's blob dir; it holds no
//     pending buffers, so it has nothing to flush or commit.

import type { Pool, PoolClient } from "pg";

/** One member of a rail's declared persist set (lifecycle above). */
export interface PersistParticipant {
  /** Stage pending buffers into the caller's open transaction. */
  flushInto(client: PoolClient): Promise<void>;
  /** Drop buffers / advance in-memory cursors — called ONLY after COMMIT. */
  commitFlush(): void;
}

/** The vocabulary for objects that deliberately do NOT participate. */
export type NonParticipantPersistence = "write-through" | "rebuild-at-boot";

/**
 * The block/slot cursor as a participant: `advanceTo` names the target before
 * each persist, flushInto stages it through the store's cursor row, and
 * commitFlush advances the store's in-memory cursor — only after COMMIT, like
 * every other participant.
 */
export class BlockCursor implements PersistParticipant {
  private target = -1;
  constructor(
    private readonly store: {
      lastBlock: number;
      persistCursorInto(client: PoolClient, block: number): Promise<void>;
    },
  ) {}

  advanceTo(block: number): void {
    this.target = block;
  }

  async flushInto(client: PoolClient): Promise<void> {
    if (this.target < 0) {
      throw new Error("BlockCursor.flushInto before advanceTo — the cursor participant has no target");
    }
    await this.store.persistCursorInto(client, this.target);
  }

  commitFlush(): void {
    this.store.lastBlock = this.target;
  }
}

/**
 * Atomic write-behind persist — the crash-safety core, in ONE place.
 *
 * Acquires one client from `pool` and, in a single BEGIN/COMMIT, runs every
 * participant's flushInto in DECLARED order; after COMMIT (and only then) runs
 * every commitFlush in the same order. A throw anywhere rolls the transaction
 * back with every buffer intact — see the module header for the full rule.
 *
 * `crashKey` preserves the TEST-ONLY fault injection: when
 * BONGTU_CRASH_BEFORE_COMMIT equals it, the persist throws at the pre-COMMIT
 * point (every row staged but nothing durable) so the atomicity window is
 * exercised deterministically. Never set outside test/pg_resume.ts and the
 * fake-participant unit test.
 */
export async function persistAtomically(
  pool: Pool,
  participants: readonly PersistParticipant[],
  crashKey: string,
): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    for (const p of participants) await p.flushInto(client);
    if (process.env.BONGTU_CRASH_BEFORE_COMMIT === crashKey) {
      throw new Error(`crash-before-commit fault injection @block ${crashKey}`);
    }
    await client.query("COMMIT");
  } catch (e) {
    try {
      await client.query("ROLLBACK");
    } catch {
      // The connection may already be dead (real crash) — keep the original error.
    }
    throw e;
  } finally {
    client.release();
  }
  for (const p of participants) p.commitFlush();
}
