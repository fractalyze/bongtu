// Indexer conformance test (SPEC §6b DoD-4). Runs the full scenario on a live
// anvil (deposit → disburse(16) → transfer → withdraw → tampered disburse),
// ingests it, and asserts every indexer invariant:
//
//   1. mirror root == contract root AND nextLeafIndex match at head
//   2. GET /path/:i for a real (single-append) leaf folds to the head root
//   3. GET /events carries the disburse ciphertext feed with correct leafIndex
//      annotations; a recipient key trial-decrypts a slice → commitment == the
//      tree leaf, and all B recovered commitments fold to the batch subtreeRoot
//   4. disclosureHash passes for the honest disburse; the tampered one ALARMS
//      ("mismatch"). §6b v2 removes the plain disburse() path, so a "withheld"
//      (nothing-published) disburse is no longer producible on-chain.
//   5. GET /path/:i for a disburse-batch leaf is refused (siblings not
//      chain-recoverable, SPEC §11-7); bad /events params are refused (400)
//   6. PUBLIC mode: /nullifiers is served (key-free) and carries the spent set;
//      /notes 404s (arbiter-only route).
//   7. ARBITER mode (SPEC §6b v2, second indexer holding the arbiter private key):
//      a recipient's GET /notes lists its disburse-batch note (value/salt/leaf,
//      spent=false); after the transfer spends it, the note reads spent=true (from
//      the input envelope alone) and the payee's new note is present; GET /path for
//      that batch leaf now folds to root() (the ledger filled the batch); the
//      arbiter /nullifiers carries the spent set; bad /notes params 400.
//
// Anvil is started + trap-killed by run.sh; this file only talks to E2E_RPC.

import { poseidon2, poseidonN } from "../../sdk/src/poseidon.js";
import { ecdhSharedSecret, poseidonDecrypt } from "../../sdk/src/note.js";
import { ImtTree } from "../../sdk/src/imt.js";
import { Indexer } from "../src/ingest.js";
import { startApi } from "../src/api/router.js";
import { runScenario } from "./scenario.js";

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
function step(t: string): void {
  console.log(`\n=== ${t} ===`);
}

function foldToRoot(leaf: bigint, siblings: bigint[], pathIndices: number[]): bigint {
  let cur = leaf;
  for (let j = 0; j < siblings.length; j++) {
    cur = pathIndices[j] === 1 ? poseidon2(siblings[j], cur) : poseidon2(cur, siblings[j]);
  }
  return cur;
}

async function get(base: string, path: string): Promise<{ status: number; body: unknown }> {
  const r = await fetch(base + path);
  return { status: r.status, body: await r.json() };
}

// Arbiter-mode conformance (SPEC §6b v2): a second indexer holding the arbiter
// private key ingests the SAME pool in two phases to exercise the note ledger's
// create -> spend transition, within-batch paths, and the arbiter /nullifiers.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function runArbiter(sc: any): Promise<void> {
  const r0 = sc.recipient0Note;
  const pay = sc.payeeNote;
  const ownerQ = (o: [string, string]): string => `/notes?owner=${o[0]},${o[1]}`;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const noteAt = (list: any[], leafIndex: number) => list.find((n) => n.leafIndex === leafIndex);

  const aix = new Indexer({ rpc: sc.rpc, pool: sc.poolAddr, startBlock: 0, authorityKey: BigInt(sc.arbiterPrivateKey) });
  ok(aix.arbiterMode === true, "second indexer is in ARBITER mode (AUTHORITY key set)");

  step("ARBITER phase 1: ingest deposit + honest disburse ONLY (up to the pre-transfer block)");
  await aix.ingest(0, sc.blockAfterHonestDisburse);
  const aapi = await startApi(aix, Number(process.env.INDEXER_TEST_PORT || 0));
  const abase = `http://127.0.0.1:${aapi.port}`;
  try {
    // recipient #0's disburse-batch note is present, unspent, decrypted from the
    // authority envelope alone (right value/salt/leafIndex).
    const n1 = await get(abase, ownerQ(r0.owner));
    ok(n1.status === 200, "GET /notes (recipient#0) 200 (arbiter)");
    const note1 = noteAt(n1.body as unknown[], r0.leafIndex);
    ok(!!note1, `recipient#0 /notes lists its batch note @${r0.leafIndex}`);
    ok(note1.value === r0.value, `note value == disbursed amount (${r0.value})`);
    ok(note1.salt === r0.salt, "note salt == the disbursed salt");
    ok(note1.commitment === sc.disburseHonest.outCommits[0], "note commitment == the on-chain batch leaf");
    ok(note1.spent === false, "recipient#0 batch note spent == false (pre-transfer)");

    step("ARBITER phase 2: ingest the rest (transfer spends @16, withdraw, tampered disburse)");
    await aix.ingest(sc.blockAfterHonestDisburse + 1);

    // Same note now reads spent=true — from the transfer's INPUT envelope, no key.
    const n2 = await get(abase, ownerQ(r0.owner));
    const note2 = noteAt(n2.body as unknown[], r0.leafIndex);
    ok(!!note2 && note2.spent === true, `recipient#0 batch note @${r0.leafIndex} now spent == true (after transfer)`);

    // The payee's transfer output note is present + unspent.
    const np = await get(abase, ownerQ(pay.owner));
    ok(np.status === 200, "GET /notes (payee) 200");
    const notep = noteAt(np.body as unknown[], pay.leafIndex);
    ok(!!notep, `payee /notes lists its transfer note @${pay.leafIndex}`);
    ok(notep.value === pay.value && notep.spent === false, `payee note value == ${pay.value}, spent == false`);

    // /notes header documents the deferred auth (v1 serves unauthenticated).
    const rawNotes = await fetch(abase + ownerQ(r0.owner));
    ok(!!rawNotes.headers.get("x-bongtu-auth"), "/notes response carries the deferred-auth header");

    // ARBITER /path into the disburse batch now serves a REAL path folding to root.
    step("ARBITER /path — within-batch leaf now servable (ledger filled the batch)");
    const bp = await get(abase, `/path/${r0.leafIndex}`);
    ok(bp.status === 200, `GET /path/${r0.leafIndex} → 200 in arbiter mode (was 422 public)`);
    const p = bp.body as { siblings: string[]; pathIndices: number[]; root: string };
    const folded = foldToRoot(BigInt(sc.disburseHonest.outCommits[0]), p.siblings.map(BigInt), p.pathIndices);
    ok(folded.toString() === sc.headRoot, `batch leaf ${r0.leafIndex} path folds to head root`);
    ok(p.root === sc.headRoot, `/path/${r0.leafIndex} reports head root`);

    // /nullifiers (also served in arbiter mode) carries every spent nullifier.
    step("ARBITER /nullifiers — spent nullifier set");
    const nf = await get(abase, "/nullifiers");
    ok(nf.status === 200, "GET /nullifiers 200 (arbiter)");
    const nfSet = new Set(nf.body as string[]);
    for (const x of sc.spentNullifiers as string[]) ok(nfSet.has(x), `/nullifiers contains ${x.slice(0, 12)}…`);

    // bad /notes params are refused.
    const bad = await get(abase, "/notes?owner=abc");
    ok(bad.status === 400, "GET /notes?owner=abc → 400 (needs two field elements)");
  } finally {
    await aapi.stop();
  }
}

async function main(): Promise<void> {
  step("SCENARIO: deploy B=16 pool + run deposit/disburse16/transfer/withdraw/tampered-disburse on anvil");
  const sc = await runScenario();
  console.log(`   pool=${sc.poolAddr} headRoot=${sc.headRoot} nextLeafIndex=${sc.nextLeafIndex}`);

  step("INGEST: replay pool events from genesis into the SDK ImtTree mirror");
  const ix = new Indexer({ rpc: sc.rpc, pool: sc.poolAddr, startBlock: 0 });
  await ix.ingest(); // throws internally if any per-insert root diverges

  // (1) mirror == contract at head
  const hd = await ix.head();
  ok(ix.tree.root().toString() === sc.headRoot, "mirror root == contract root at head");
  ok(ix.tree.root() === hd.root, "mirror root == live pool.root()");
  ok(ix.tree.nextLeafIndex() === sc.nextLeafIndex, `mirror nextLeafIndex == contract (${sc.nextLeafIndex})`);
  ok(hd.nextLeafIndex === sc.nextLeafIndex, "head() nextLeafIndex == contract");

  const api = await startApi(ix, Number(process.env.INDEXER_TEST_PORT || 0));
  const base = `http://127.0.0.1:${api.port}`;
  try {
    // /head
    step("API /head");
    const headRes = await get(base, "/head");
    ok(headRes.status === 200, "GET /head 200");
    ok((headRes.body as { root: string }).root === sc.headRoot, "/head root == contract root");
    ok((headRes.body as { nextLeafIndex: number }).nextLeafIndex === sc.nextLeafIndex, "/head nextLeafIndex == contract");

    // (2) /path for a real single-append leaf folds to head root
    step("API /path/:i — real leaf folds to head root");
    for (const sl of sc.singleLeaves) {
      const pr = await get(base, `/path/${sl.leafIndex}`);
      ok(pr.status === 200, `GET /path/${sl.leafIndex} 200`);
      const p = pr.body as { siblings: string[]; pathIndices: number[]; root: string };
      const folded = foldToRoot(BigInt(sl.commitment), p.siblings.map(BigInt), p.pathIndices);
      ok(folded.toString() === sc.headRoot, `leaf ${sl.leafIndex} merkle path folds to head root`);
      ok(p.root === sc.headRoot, `/path/${sl.leafIndex} reports head root`);
    }

    // (3) /events ciphertext feed + trial-decrypt
    step("API /events — disburse ciphertext feed + recipient trial-decrypt");
    const evRes = await get(base, "/events");
    ok(evRes.status === 200, "GET /events 200");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const feed = evRes.body as any[];
    const kinds = feed.map((e) => e.kind).join(",");
    ok(kinds === "deposit,disburse,transfer,withdraw,disburse", `feed kinds in chain order: ${kinds}`);

    const honest = feed.find((e) => e.kind === "disburse" && e.slices[0]?.leafIndex === sc.disburseHonest.startLeafIndex);
    ok(!!honest, "honest disburse present in feed");
    ok(honest.ecdhPublicKey[0] === sc.disburseHonest.ecdhPublicKey[0]
      && honest.ecdhPublicKey[1] === sc.disburseHonest.ecdhPublicKey[1], "feed ecdhPublicKey == on-chain ephemeral pub");
    ok(honest.encryptionNonce === sc.disburseHonest.nonce, "feed encryptionNonce == on-chain nonce");
    ok(honest.slices.length === sc.B + 1, `disburse has ${sc.B} receiver slices + 1 authority tail`);
    for (let i = 0; i < sc.B; i++) {
      ok(honest.slices[i].leafIndex === sc.disburseHonest.startLeafIndex + i,
        `slice ${i} leafIndex annotation == ${sc.disburseHonest.startLeafIndex + i}`);
    }
    ok(honest.slices[sc.B].leafIndex === null, "authority tail slice has no leafIndex");

    // trial-decrypt every receiver slice with its recipient key; recover the note
    const nonce = BigInt(honest.encryptionNonce);
    const ephemeralPub: [bigint, bigint] = [BigInt(honest.ecdhPublicKey[0]), BigInt(honest.ecdhPublicKey[1])];
    const recovered: bigint[] = [];
    for (let i = 0; i < sc.B; i++) {
      const s = honest.slices[i];
      const ct = (honest.ciphertext as string[]).slice(s.offset, s.offset + s.elts).map(BigInt);
      const priv = BigInt(sc.disburseHonest.recipientPrivs[i]);
      const shared = ecdhSharedSecret(priv, ephemeralPub);
      const [value, salt] = poseidonDecrypt(ct, shared, nonce, 2);
      const pub = sc.disburseHonest.recipientPubs[i];
      const c = poseidonN([value, salt, BigInt(pub[0]), BigInt(pub[1])]);
      recovered.push(c);
      if (i === 0) {
        ok(c.toString() === sc.disburseHonest.outCommits[0], "trial-decrypt slice 0 → commitment == the tree leaf");
        ok(value.toString() === sc.disburseHonest.amounts[0], "recovered value == recipient #0 disbursed amount");
      }
    }
    // all B recovered commitments fold to the batch subtree root the indexer ingested
    const subRoot = new ImtTree(sc.H, sc.B).computeSubtreeRoot(recovered);
    ok(subRoot.toString() === sc.disburseHonest.subtreeRoot, `all ${sc.B} recovered commitments fold to the batch subtreeRoot`);

    // (4) disclosure: honest passes; tampered alarms "mismatch". §6b v2 removes
    // the plain disburse() path, so "withheld" is no longer producible on-chain.
    step("disclosure: honest PASS + tampered MISMATCH alarm (enforced disclosure)");
    ok(honest.disclosure === "verified", "honest disburse disclosureHash status == verified");
    const tampered = feed.find((e) => e.kind === "disburse" && e.slices[0]?.leafIndex === sc.tamperedStartLeafIndex);
    ok(!!tampered, "tampered disburse present in feed");
    ok(tampered.disclosure === "mismatch", "tampered disburse disclosureHash status == mismatch (ALARM)");
    const alarmRes = await get(base, "/alarms");
    ok(alarmRes.status === 200, "GET /alarms 200");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const alarms = alarmRes.body as any[];
    ok(alarms.length === 1, "one disclosure alarm surfaced (tampered mismatch)");
    ok(alarms[0].status === "mismatch" && alarms[0].startLeafIndex === sc.tamperedStartLeafIndex,
      "alarm[0] == mismatch at the tampered batch");

    // (5) /path into a disburse batch leaf is refused; bad /events params are 400
    step("API /path — disburse-batch leaf refused (siblings not chain-recoverable)");
    const batchPath = await get(base, `/path/${sc.disburseHonest.startLeafIndex}`);
    ok(batchPath.status === 422, `GET /path/${sc.disburseHonest.startLeafIndex} (batch leaf) → 422`);
    ok((batchPath.body as { reason: string }).reason === "batch-leaf", "422 reason == batch-leaf");
    const tamperedPath = await get(base, `/path/${sc.tamperedStartLeafIndex}`);
    ok(tamperedPath.status === 422, `GET /path/${sc.tamperedStartLeafIndex} (tampered-batch leaf) → 422`);
    const badCursor = await get(base, "/events?cursor=abc");
    ok(badCursor.status === 400, "GET /events?cursor=abc → 400");
    const badLimit = await get(base, "/events?limit=0");
    ok(badLimit.status === 400, "GET /events?limit=0 → 400");

    step("PUBLIC mode: /nullifiers served (key-free), /notes 404 (arbiter-only)");
    const nfRes = await get(base, "/nullifiers");
    ok(nfRes.status === 200, "GET /nullifiers 200 (public)");
    const nfSet = new Set(nfRes.body as string[]);
    for (const nf of sc.spentNullifiers) ok(nfSet.has(nf), `/nullifiers contains spent nullifier ${nf.slice(0, 12)}…`);
    const notesPublic = await get(base, `/notes?owner=${sc.recipient0Note.owner[0]},${sc.recipient0Note.owner[1]}`);
    ok(notesPublic.status === 404, "GET /notes → 404 in public mode (route not registered)");
  } finally {
    await api.stop();
  }

  // ======================= ARBITER MODE (SPEC §6b v2) =======================
  // A SECOND indexer built WITH the arbiter private key, ingesting the SAME pool.
  // It decrypts every op's authority envelope → a note ledger + within-batch paths,
  // with spent status derived from envelopes ALONE (no user key, no nullifier link).
  await runArbiter(sc);

  console.log(`\n${failures === 0 ? "INDEXER TEST PASS — mirror==contract, /path folds, feed trial-decrypts, disclosureHash pass + tamper alarm, arbiter note-ledger spent-transition + batch paths + /nullifiers" : `INDEXER TEST FAIL — ${failures} assertion(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nINDEXER TEST ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
