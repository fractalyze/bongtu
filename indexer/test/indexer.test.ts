// Indexer conformance test (SPEC §6b DoD-4). Runs the full scenario on a live
// anvil (deposit → disburse(16) → transfer → withdraw → tampered disburse →
// plain disburse), ingests it, and asserts every indexer invariant:
//
//   1. mirror root == contract root AND nextLeafIndex match at head
//   2. GET /path/:i for a real (single-append) leaf folds to the head root
//   3. GET /events carries the disburse ciphertext feed with correct leafIndex
//      annotations; a recipient key trial-decrypts a slice → commitment == the
//      tree leaf, and all B recovered commitments fold to the batch subtreeRoot
//   4. disclosureHash passes for the honest disburse; the tampered one ALARMS
//      ("mismatch"); the plain (no-ciphertext) one still appears in the feed
//      and ALARMS as "withheld"
//   5. GET /path/:i for a disburse-batch leaf is refused (siblings not
//      chain-recoverable, SPEC §11-7); bad /events params are refused (400)
//
// Anvil is started + trap-killed by run.sh; this file only talks to E2E_RPC.

import { poseidon2, poseidonN } from "../../sdk/src/poseidon.js";
import { ecdhSharedSecret, poseidonDecrypt } from "../../sdk/src/note.js";
import { ImtTree } from "../../sdk/src/imt.js";
import { Indexer } from "../src/ingest.js";
import { startApi } from "../src/api.js";
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

async function main(): Promise<void> {
  step("SCENARIO: deploy B=16 pool + run deposit/disburse16/transfer/withdraw/tampered-disburse on anvil");
  const sc = await runScenario();
  console.log(`   pool=${sc.poolAddr} headRoot=${sc.headRoot} nextLeafIndex=${sc.nextLeafIndex}`);

  step("INGEST: replay pool events from genesis into the SDK ImtTree mirror");
  const ix = new Indexer({ rpc: sc.rpc, pool: sc.poolAddr, startBlock: 0 });
  await ix.ingest(); // throws internally if any per-insert root diverges

  // (1) mirror == contract at head
  const hd = await ix.head();
  ok(ix.mirror.getRoot().toString() === sc.headRoot, "mirror root == contract root at head");
  ok(ix.mirror.getRoot() === hd.root, "mirror root == live pool.root()");
  ok(ix.mirror.getNextLeafIndex() === sc.nextLeafIndex, `mirror nextLeafIndex == contract (${sc.nextLeafIndex})`);
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
    ok(kinds === "deposit,disburse,transfer,withdraw,disburse,disburse", `feed kinds in chain order: ${kinds}`);

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

    // (4) disclosure: honest passes; tampered alarms "mismatch"; plain disburse
    // still appears in the feed and alarms "withheld"
    step("disclosure: honest PASS + tampered MISMATCH alarm + plain WITHHELD alarm");
    ok(honest.disclosure === "verified", "honest disburse disclosureHash status == verified");
    const tampered = feed.find((e) => e.kind === "disburse" && e.slices[0]?.leafIndex === sc.tamperedStartLeafIndex);
    ok(!!tampered, "tampered disburse present in feed");
    ok(tampered.disclosure === "mismatch", "tampered disburse disclosureHash status == mismatch (ALARM)");
    const plain = feed.find((e) => e.kind === "disburse" && e.disclosure === "withheld");
    ok(!!plain, "plain disburse (no ciphertext event) present in feed");
    ok(plain.ciphertext.length === 0 && plain.slices.length === 0, "plain disburse entry has empty ciphertext + slices");
    const alarmRes = await get(base, "/alarms");
    ok(alarmRes.status === 200, "GET /alarms 200");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const alarms = alarmRes.body as any[];
    ok(alarms.length === 2, "two disclosure alarms surfaced (tampered + withheld)");
    ok(alarms[0].status === "mismatch" && alarms[0].startLeafIndex === sc.tamperedStartLeafIndex,
      "alarm[0] == mismatch at the tampered batch");
    ok(alarms[1].status === "withheld" && alarms[1].startLeafIndex === sc.plainStartLeafIndex,
      "alarm[1] == withheld at the plain-disburse batch");

    // (5) /path into a disburse batch leaf is refused; bad /events params are 400
    step("API /path — disburse-batch leaf refused (siblings not chain-recoverable)");
    const batchPath = await get(base, `/path/${sc.disburseHonest.startLeafIndex}`);
    ok(batchPath.status === 422, `GET /path/${sc.disburseHonest.startLeafIndex} (batch leaf) → 422`);
    ok((batchPath.body as { reason: string }).reason === "batch-leaf", "422 reason == batch-leaf");
    const plainPath = await get(base, `/path/${sc.plainStartLeafIndex}`);
    ok(plainPath.status === 422, `GET /path/${sc.plainStartLeafIndex} (plain-disburse batch leaf) → 422`);
    const badCursor = await get(base, "/events?cursor=abc");
    ok(badCursor.status === 400, "GET /events?cursor=abc → 400");
    const badLimit = await get(base, "/events?limit=0");
    ok(badLimit.status === 400, "GET /events?limit=0 → 400");
  } finally {
    await api.stop();
  }

  console.log(`\n${failures === 0 ? "INDEXER TEST PASS — mirror==contract, /path folds, feed trial-decrypts, disclosureHash pass + tamper alarm" : `INDEXER TEST FAIL — ${failures} assertion(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nINDEXER TEST ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
