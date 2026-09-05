// CPU-lane atomicity contract for the declared-participant persist
// (src/persist.ts), driven with FAKE participants — no Postgres in the loop.
// Pins the contract the live-Postgres suites (pg_integration.sh) exercise end
// to end:
//   - flushInto runs in DECLARED order inside BEGIN..COMMIT, and commitFlush
//     runs in the same declared order strictly AFTER COMMIT;
//   - a participant throwing mid-flush leaves EVERY buffer intact (no
//     commitFlush called anywhere) and the cursor unadvanced (ROLLBACK, never
//     COMMIT);
//   - the BONGTU_CRASH_BEFORE_COMMIT fault hook throws at the staged-but-not-
//     durable point with the same rollback discipline.
//
//   node --import tsx --test test/persist.test.ts   (part of test:unit)

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Pool, PoolClient } from "pg";

import { BlockCursor, persistAtomically, type PersistParticipant } from "../src/persist.js";

/** A pg Pool double whose client records SQL verbs into the shared event log. */
function fakePool(log: string[]): Pool {
  const client = {
    query: async (sql: string) => {
      log.push(sql.trimStart().split(/[\s(]/, 1)[0]); // BEGIN / COMMIT / ROLLBACK / INSERT
      return { rows: [] };
    },
    release: (): void => {
      log.push("release");
    },
  };
  return { connect: async () => client } as unknown as Pool;
}

function fakeParticipant(name: string, log: string[], opts: { throwOnFlush?: boolean } = {}): PersistParticipant {
  return {
    async flushInto(_client: PoolClient): Promise<void> {
      if (opts.throwOnFlush) {
        log.push(`flush:${name}:THROW`);
        throw new Error(`${name} exploded mid-flush`);
      }
      log.push(`flush:${name}`);
    },
    commitFlush(): void {
      log.push(`commit:${name}`);
    },
  };
}

/** A store double for the REAL BlockCursor participant: the lastBlock setter
 *  logs, so the cursor's commit position in the sequence is observable. */
function fakeStore(log: string[]): { lastBlock: number; persistCursorInto(client: PoolClient, block: number): Promise<void> } {
  const state = { last: -1 };
  return {
    get lastBlock(): number {
      return state.last;
    },
    set lastBlock(v: number) {
      log.push(`commit:cursor@${v}`);
      state.last = v;
    },
    async persistCursorInto(_client: PoolClient, block: number): Promise<void> {
      log.push(`flush:cursor@${block}`);
    },
  };
}

test("success: flushInto in declared order, commitFlush in declared order strictly AFTER COMMIT", async () => {
  const log: string[] = [];
  const store = fakeStore(log);
  const cursor = new BlockCursor(store);
  cursor.advanceTo(7);
  await persistAtomically(fakePool(log), [fakeParticipant("a", log), fakeParticipant("b", log), cursor], "7");
  assert.deepEqual(log, [
    "BEGIN",
    "flush:a",
    "flush:b",
    "flush:cursor@7",
    "COMMIT",
    "release",
    "commit:a",
    "commit:b",
    "commit:cursor@7",
  ]);
  assert.equal(store.lastBlock, 7, "cursor advanced only via its own commitFlush, after COMMIT");
});

test("a participant throwing mid-flush: every buffer intact, cursor unadvanced, transaction rolled back", async () => {
  const log: string[] = [];
  const store = fakeStore(log);
  const cursor = new BlockCursor(store);
  cursor.advanceTo(9);
  const participants = [
    fakeParticipant("a", log),
    fakeParticipant("bad", log, { throwOnFlush: true }),
    fakeParticipant("c", log),
    cursor,
  ];
  await assert.rejects(() => persistAtomically(fakePool(log), participants, "9"), /bad exploded mid-flush/);
  assert.deepEqual(log, ["BEGIN", "flush:a", "flush:bad:THROW", "ROLLBACK", "release"]);
  assert.ok(!log.some((e) => e.startsWith("commit:")), "no commitFlush reached ANY participant");
  assert.ok(!log.includes("COMMIT"), "the transaction never committed");
  assert.equal(store.lastBlock, -1, "the in-memory cursor did not advance");
});

test("BONGTU_CRASH_BEFORE_COMMIT: throws at the staged-but-not-durable point, same rollback discipline", async () => {
  const log: string[] = [];
  const store = fakeStore(log);
  const cursor = new BlockCursor(store);
  cursor.advanceTo(42);
  process.env.BONGTU_CRASH_BEFORE_COMMIT = "42";
  try {
    await assert.rejects(
      () => persistAtomically(fakePool(log), [fakeParticipant("a", log), cursor], "42"),
      /crash-before-commit fault injection/,
    );
  } finally {
    delete process.env.BONGTU_CRASH_BEFORE_COMMIT;
  }
  assert.deepEqual(log, ["BEGIN", "flush:a", "flush:cursor@42", "ROLLBACK", "release"]);
  assert.equal(store.lastBlock, -1, "the fault fired AFTER staging, BEFORE anything became durable");
});
