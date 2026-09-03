// DisclosureStatus classifier unit test — ANVIL-FREE, pure computation.
//
// The conformance scenario can only reach the pass and "mismatch" statuses
// (§6b v2 removed plain disburse(), and the honest leg publishes in full), so
// the classifier's "unverifiable"/"withheld" branches — and the branch ORDERING
// that keeps a hash-matching receiver-only publish off the alarm channel — are
// pinned here, where a synthetic ciphertext list costs nothing.
//
//   node --import tsx test/disclosure.test.ts   # (== npm run test:disclosure)

import { disclosureChain } from "@bongtu/core/envelope";
import { poseidon2, FIELD_PRIME } from "@bongtu/core/poseidon";
import { verifyDisclosure, verifyConsumerDisclosure } from "../src/disclosure.js";

const failures = { count: 0 };
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures.count++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
function step(t: string): void {
  console.log(`\n=== ${t} ===`);
}

const B = 2;
const RECV = B * 4;
const TX = "0xtest";
const full = Array.from({ length: RECV + 3 }, (_, i) => BigInt(1000 + i));
const dh = disclosureChain(full);

step("full receiver ++ authority publish whose chain matches");
const v = verifyDisclosure(full, dh, B, TX, 0);
ok(v.status === "verified", "full-length matching publish → verified");
ok(v.emittedCount === RECV + 3 && v.receiverCount === RECV, "emitted/receiver counts reported");
ok(v.recomputed === dh.toString() && v.expected === dh.toString(), "recomputed == expected (decimal)");

step("mismatch: full-length publish whose chain does NOT match (proven tamper)");
const tampered = [...full];
tampered[0] = tampered[0] + 1n;
const m = verifyDisclosure(tampered, dh, B, TX, 0);
ok(m.status === "mismatch", "tampered full-length publish → mismatch");
ok(m.recomputed !== m.expected, "mismatch carries the diverging recomputed value");

step("unverifiable: receiver-only publish (the chain cannot be completed)");
const recvOnly = full.slice(0, RECV);
const u = verifyDisclosure(recvOnly, dh, B, TX, 5);
ok(u.status === "unverifiable", "exactly B*4 elements without a hash match → unverifiable");
ok(u.emittedCount === RECV && u.startLeafIndex === 5, "unverifiable carries emittedCount + startLeafIndex");

// Branch ordering: a receiver-only publish that happens to hash to the
// committed value IS the committed chain — it must not read as a gap.
const u2 = verifyDisclosure(recvOnly, disclosureChain(recvOnly), B, TX, 5);
ok(u2.status === "verified", "receiver-only publish that hash-matches → verified (match beats length)");

step("withheld: nothing published at all");
const w = verifyDisclosure([], dh, B, TX, 7);
ok(w.status === "withheld", "empty publish → withheld");
ok(w.recomputed === "0", "withheld recomputed == the chain seed (0)");

// A nonzero publish SHORTER than the receiver run cannot be an honest
// receiver-only emission → structurally broken feed, proven tamper.
const short = verifyDisclosure(full.slice(0, 3), dh, B, TX, 0);
ok(short.status === "mismatch", "short nonzero publish (< B*4) → mismatch");

// ---- consumer disburse (OPMOD §4.4): the three-check verdict --------------
// disclosure = receiverCts[4B] ++ viewTags[B] ++ outputCommitments[B], with an
// INDEPENDENT commitment-run fold to the on-chain subtreeRoot — the check that
// makes the public batch FILL safe (a bad publish alarms instead of 500ing).

const CB = 4;
const cCts = Array.from({ length: 4 * CB }, (_, i) => BigInt(9000 + i));
const cTags = [1n, 2n, 3n, 4n];
const cCommits = [11n, 22n, 33n, 44n];
const cDisclosure = [...cCts, ...cTags, ...cCommits];
const cDh = disclosureChain(cDisclosure);
const cSub = poseidon2(poseidon2(11n, 22n), poseidon2(33n, 44n));

step("consumer: all three checks green → verified + the fill material");
const cv = verifyConsumerDisclosure(cDisclosure, cDh, cSub, CB, TX, 16);
ok(cv.result.status === "verified", "full checks → verified");
ok(cv.leaves !== null && cv.leaves.join(",") === cCommits.join(","), "leaves == the commitment run (the fill material)");
ok(cv.result.receiverCount === 4 * CB && cv.result.startLeafIndex === 16, "receiverCount/startLeafIndex reported");

step("consumer: publication gaps map onto the enterprise classes");
ok(verifyConsumerDisclosure([], cDh, cSub, CB, TX, 16).result.status === "withheld", "absent publish → withheld");
ok(verifyConsumerDisclosure(cDisclosure.slice(0, 10), cDh, cSub, CB, TX, 16).result.status === "unverifiable",
  "truncated publish → unverifiable");

step("consumer: canonical-form binding — an element >= p is a mismatch alarm");
const nonCanon = [...cDisclosure];
nonCanon[3] = nonCanon[3] + FIELD_PRIME; // mod-p alias of the proven element
const cnc = verifyConsumerDisclosure(nonCanon, cDh, cSub, CB, TX, 16);
ok(cnc.result.status === "mismatch" && cnc.leaves === null, "aliased element → mismatch, no fill material");

step("consumer: fold mismatch vs disclosureHash → mismatch");
const cTampered = [...cDisclosure];
cTampered[0] = cTampered[0] + 1n;
const ctm = verifyConsumerDisclosure(cTampered, cDh, cSub, CB, TX, 16);
ok(ctm.result.status === "mismatch" && ctm.result.recomputed !== ctm.result.expected, "dh-diverging publish → mismatch");
ok(ctm.leaves === null, "no fill material on a dh mismatch");

step("consumer: BAD FOLD — dh matches the array, commitments don't fold to subtreeRoot");
const badCommits = [11n, 22n, 33n, 45n];
const badArray = [...cCts, ...cTags, ...badCommits];
const bf = verifyConsumerDisclosure(badArray, disclosureChain(badArray), cSub, CB, TX, 16);
ok(bf.result.status === "mismatch", "check-3 failure → mismatch alarm, never a fill");
ok(bf.result.recomputed === poseidon2(poseidon2(11n, 22n), poseidon2(33n, 45n)).toString()
  && bf.result.expected === cSub.toString(),
  "check-3 alarm carries (fold, subtreeRoot) as (recomputed, expected)");
ok(bf.leaves === null, "no fill material on a bad fold");

console.log(`\n${failures.count === 0 ? "DISCLOSURE TEST PASS — all four DisclosureStatus branches + branch ordering pinned + the consumer three-check verdict" : `DISCLOSURE TEST FAIL — ${failures.count} assertion(s)`}`);
process.exit(failures.count === 0 ? 0 : 1);
