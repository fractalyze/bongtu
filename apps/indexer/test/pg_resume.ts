// Crash-in-persist-window resume test (U-I2 atomicity) — the BLOCKER's proof.
//
// The hazard being closed: ingest used to persist the store rows, the ledger rows,
// and the block cursor in THREE separate transactions. A crash after the leaves
// committed but before the cursor advanced left the durable `leaves` table AHEAD
// of the cursor; on boot, bootPostgres rebuilds the frontier from the leaves (at
// HEAD) yet resumes from cursor+1 (an OLD block), so its reconstructed-root ==
// contract-root-at-cursor assert throws forever → a PERMANENT WEDGE.
//
// The fix makes persist ONE transaction (leaves + every other derived row + the
// cursor commit together). This test proves the wedge is now UNREACHABLE by
// construction, driving the exact atomic boundary deterministically (no racy kill):
//
//   ref     : a clean in-memory ingest of the whole scenario = the source of truth.
//   phase 1 : ingest only blocks [0..A] into Postgres, atomic persist → cursor=A.
//   phase 2 : resume from A+1 but CRASH right before COMMIT (fault injected via
//             BONGTU_CRASH_BEFORE_COMMIT). Assert the txn ROLLED BACK ATOMICALLY:
//             the cursor is STILL A and the leaves table did NOT advance past A.
//             (With the old 3-txn code the leaves would have committed while the
//             cursor lagged — precisely the wedged state — so this assert is the
//             differential that distinguishes atomic from non-atomic.)
//   phase 3 : a fresh instance boots from the post-crash DB — it must NOT wedge,
//             must resume A+1..head, and must converge byte-identically to `ref`.
//   phase 3.5: re-ingest an already-persisted range — idempotent, no double-count.
//
//   node --import tsx test/pg_resume.ts <fixtures.json>   (env: DATABASE_URL, RPC)

import { readFileSync } from "node:fs";
import { Pool } from "pg";
import { Indexer } from "../src/ingest.js";
import type { ChainConfig } from "../src/chain.js";

const fixturesPath = process.argv[2];
const databaseUrl = process.env.DATABASE_URL;
if (!fixturesPath) throw new Error("usage: pg_resume.ts <fixtures.json>");
if (!databaseUrl) throw new Error("pg_resume.ts requires DATABASE_URL (the crash-test database)");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const sc: any = JSON.parse(readFileSync(fixturesPath, "utf8"));

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
}

const rpc = process.env.RPC || process.env.E2E_RPC || sc.rpc;
const baseCfg: ChainConfig = {
  rpc,
  pool: sc.poolAddr,
  startBlock: 0,
  authorityKey: BigInt(sc.arbiterPrivateKey),
};

// A compact fingerprint of an ingested indexer's served state — the fields the
// resumed Postgres instance must reproduce exactly from the clean in-memory run.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fingerprint(ix: Indexer): any {
  const [ox, oy] = sc.recipient0Note.owner as [string, string];
  const r0Notes = ix.ledger!.notesOf(BigInt(ox), BigInt(oy));
  const r0Batch = r0Notes.find((n) => n.leafIndex === sc.recipient0Note.leafIndex);
  const r0History = ix.ledger!.historyOf(BigInt(ox), BigInt(oy));
  return {
    root: ix.tree.root().toString(),
    nli: ix.tree.nextLeafIndex(),
    events: ix.store.allEvents().length,
    nullifiers: [...ix.store.nullifiers()].sort(),
    disclosureAlarms: ix.store.getAlarms().length,
    envelopeAlarms: ix.ledger!.getEnvelopeAlarms().length,
    r0NoteCount: r0Notes.length,
    r0BatchSpent: r0Batch?.spent ?? null,
    r0HistoryKinds: r0History.map((h) => h.kind).sort(),
  };
}

async function cursorOf(q: Pool): Promise<number> {
  const r = await q.query("SELECT last_block FROM ingest_cursor WHERE id = 1");
  return r.rows.length > 0 ? Number(r.rows[0].last_block) : -1;
}
async function maxLeafIndex(q: Pool): Promise<number> {
  const r = await q.query("SELECT COALESCE(MAX(leaf_index), -1) AS m FROM leaves");
  return Number(r.rows[0].m);
}
async function countEvents(q: Pool): Promise<number> {
  const r = await q.query("SELECT COUNT(*)::int AS c FROM events");
  return Number(r.rows[0].c);
}

async function main(): Promise<void> {
  const A = Number(sc.blockAfterHonestDisburse); // intermediate block: deposit + honest disburse
  const q = new Pool({ connectionString: databaseUrl });

  // ---- reference: a clean in-memory ingest of the WHOLE scenario ----
  console.log("== reference: clean in-memory ingest (source of truth) ==");
  const ixRef = new Indexer(baseCfg); // no databaseUrl → in-memory adapters
  await ixRef.ingest();
  const ref = fingerprint(ixRef);
  const headNum = Number(await ixRef.provider.getBlockNumber());
  ok(ref.root === sc.headRoot, `reference mirror root == scenario head root (head block ${headNum}, A=${A})`);
  ok(A > 0 && A < headNum, `intermediate block A=${A} is strictly inside (0, ${headNum}]`);

  // ---- phase 1: ingest [0..A] into Postgres, atomic persist ----
  console.log("== phase 1: partial ingest [0..A] → atomic persist (cursor should reach A) ==");
  const cfgPg: ChainConfig = { ...baseCfg, databaseUrl };
  const ix1 = new Indexer(cfgPg);
  await ix1.ingest(0, A);
  const cursor1 = await cursorOf(q);
  const maxLeaf1 = await maxLeafIndex(q);
  const nliAtA = ix1.tree.nextLeafIndex();
  ok(cursor1 === A, `durable cursor == A (${A}) after phase 1`);
  ok(maxLeaf1 >= 0 && maxLeaf1 < nliAtA, `leaves table consistent with A (maxLeafIndex ${maxLeaf1} < nextLeafIndex ${nliAtA})`);
  await ix1.close();

  // ---- phase 2: resume from A+1 but CRASH before COMMIT ----
  console.log("== phase 2: resume A+1..head, fault-inject a crash BEFORE COMMIT ==");
  process.env.BONGTU_CRASH_BEFORE_COMMIT = String(headNum);
  const ix2 = new Indexer(cfgPg);
  let crashed = false;
  try {
    await ix2.ingest(A + 1);
  } catch (e) {
    crashed = /crash-before-commit/.test((e as Error).message);
  }
  delete process.env.BONGTU_CRASH_BEFORE_COMMIT;
  await ix2.close();
  ok(crashed, "phase 2 threw the injected crash-before-commit at the persist boundary");
  // The ATOMICITY differential: the whole persist txn rolled back, so NEITHER the
  // cursor NOR the leaves advanced. A non-atomic (per-write-txn) persist would have
  // committed the batch-2 leaves before the crash → leaves ahead of the cursor.
  const cursorAfterCrash = await cursorOf(q);
  const maxLeafAfterCrash = await maxLeafIndex(q);
  ok(cursorAfterCrash === A, `cursor STILL == A (${A}) after the crash (rolled back)`);
  ok(maxLeafAfterCrash === maxLeaf1, `leaves table STILL at A (maxLeafIndex ${maxLeafAfterCrash}) — did NOT advance ahead of the cursor`);

  // ---- phase 3: fresh instance boots from the post-crash DB and resumes ----
  console.log("== phase 3: fresh boot from the post-crash DB → resume, must not wedge ==");
  const ix3 = new Indexer(cfgPg);
  let bootWedged: string | null = null;
  try {
    await ix3.ingest(); // bootPostgres resumes from cursor A; applyLogs A+1..head
  } catch (e) {
    bootWedged = (e as Error).message;
  }
  ok(bootWedged === null, `boot + resume did NOT wedge${bootWedged ? ` (threw: ${bootWedged})` : ""}`);
  const cursor3 = await cursorOf(q);
  ok(cursor3 === headNum, `durable cursor advanced to head (${headNum}) after recovery`);
  const fp3 = fingerprint(ix3);
  ok(JSON.stringify(fp3) === JSON.stringify(ref), "recovered served state is byte-identical to the clean reference");
  if (JSON.stringify(fp3) !== JSON.stringify(ref)) {
    console.log("      ref:", JSON.stringify(ref));
    console.log("      got:", JSON.stringify(fp3));
  }

  // ---- phase 3.5: re-ingest an already-persisted range — idempotent ----
  console.log("== phase 3.5: re-ingest [A+1..head] over already-persisted rows → no double-count ==");
  const eventsBefore = await countEvents(q);
  const fpBefore = fingerprint(ix3);
  let reingestThrew: string | null = null;
  try {
    await ix3.ingest(A + 1); // tree already built → bootPostgres NOT re-run; forces a real replay
  } catch (e) {
    reingestThrew = (e as Error).message;
  }
  const eventsAfter = await countEvents(q);
  const fpAfter = fingerprint(ix3);
  ok(reingestThrew === null, `re-ingest of a persisted range did not throw${reingestThrew ? ` (${reingestThrew})` : ""}`);
  ok(eventsAfter === eventsBefore, `events row count unchanged (${eventsBefore}) — no duplicate rows`);
  ok(JSON.stringify(fpAfter) === JSON.stringify(fpBefore), "served state unchanged after re-ingest (idempotent)");
  await ix3.close();

  await q.end();

  console.log(`\nSUMMARY resume cursor A=${A}→head=${headNum} events=${eventsAfter} nli=${fp3.nli} root=${fp3.root}`);
  if (failures > 0) {
    console.log(`PG RESUME GATE: FAIL — ${failures} assertion(s)`);
    process.exit(1);
  }
  console.log("PG RESUME GATE: PASS (atomic persist closes the crash-in-persist-window wedge; resume converges idempotently)");
  process.exit(0);
}

main().catch((e) => {
  console.error("PG RESUME ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
