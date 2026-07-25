// Assert one running Postgres-backed indexer instance serves the scenario's state
// correctly, over HTTP with the SAME arbiter read-auth the wallet uses. Run once
// per instance (fresh boot and post-restart) by pg_integration.sh; it prints a
// SUMMARY line the shell diffs across the two runs to prove resume was stable.
//
//   node --import tsx test/pg_assert.ts <baseUrl> <fixtures.json>

import { readFileSync } from "node:fs";
import { packPubkey } from "@bongtu/core/pubkey";
import { signNotesAuth, notesAuthMessage, packSignature } from "@bongtu/core/eddsa";

const base = process.argv[2];
const fixturesPath = process.argv[3];
if (!base || !fixturesPath) throw new Error("usage: pg_assert.ts <baseUrl> <fixtures.json>");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const sc: any = JSON.parse(readFileSync(fixturesPath, "utf8"));

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
}

async function get(path: string): Promise<{ status: number; body: unknown }> {
  const r = await fetch(base + path);
  return { status: r.status, body: await r.json() };
}

// A /notes|/history request is authenticated: compressed owner + fresh ts + a bjj
// EdDSA-Poseidon sig over Poseidon(ownerPub.x, ownerPub.y, ts), signed by the owner.
function authedQ(route: string, owner: [string, string], signPriv: string): string {
  const ts = Math.floor(Date.now() / 1000);
  const pub: [bigint, bigint] = [BigInt(owner[0]), BigInt(owner[1])];
  const sig = packSignature(signNotesAuth(BigInt(signPriv), notesAuthMessage(pub, ts)));
  return `${route}?owner=${packPubkey(pub)}&ts=${ts}&sig=${sig}`;
}

async function main(): Promise<void> {
  const r0 = sc.recipient0Note;

  const head = await get("/head");
  ok(head.status === 200, "GET /head 200");
  const hb = head.body as { root: string; nextLeafIndex: number };
  ok(hb.root === sc.headRoot, "/head root == scenario head root (reconstructed mirror)");
  ok(hb.nextLeafIndex === sc.nextLeafIndex, `/head nextLeafIndex == ${sc.nextLeafIndex}`);

  const notes = await get(authedQ("/notes", r0.owner, sc.recipient0PrivateKey));
  ok(notes.status === 200, "GET /notes (recipient#0, signed) 200");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const notesBody = notes.body as any[];
  const n16 = notesBody.find((n) => n.leafIndex === r0.leafIndex);
  ok(!!n16, `recipient#0 /notes lists its batch note @${r0.leafIndex}`);
  ok(!!n16 && n16.value === r0.value, `batch note value == ${r0.value}`);
  ok(!!n16 && n16.commitment === sc.disburseHonest.outCommits[0], "batch note commitment == on-chain leaf");
  ok(!!n16 && n16.spent === true, "batch note spent == true (transfer consumed it — from the persisted ledger)");
  const notesCount = notesBody.length;

  const hist = await get(authedQ("/history", r0.owner, sc.recipient0PrivateKey));
  ok(hist.status === 200, "GET /history (recipient#0, signed) 200");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const histBody = hist.body as any[];
  ok(histBody.length === 3, `recipient#0 /history has 3 items (got ${histBody.length})`);
  const kinds = new Set(histBody.map((h) => h.kind));
  ok(kinds.has("received") && kinds.has("sent") && kinds.has("withdraw"), "history carries received + sent + withdraw");
  const recv = histBody.find((h) => h.kind === "received");
  ok(!!recv && recv.amount === r0.value, `received amount == disbursed amount (${r0.value})`);
  ok(
    histBody.every((x, i) => i === 0 || histBody[i - 1].seq > x.seq),
    "history sorted by seq desc (newest-first, seq survived restart)",
  );

  // The line the shell greps + diffs across the fresh and resumed instances.
  console.log(`SUMMARY notesCount=${notesCount} headRoot=${hb.root} nli=${hb.nextLeafIndex} historyLen=${histBody.length}`);
  if (failures > 0) {
    console.log(`PG ASSERT FAIL — ${failures} assertion(s)`);
    process.exit(1);
  }
  console.log("PG ASSERT PASS");
  process.exit(0);
}

main().catch((e) => {
  console.error("PG ASSERT ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
