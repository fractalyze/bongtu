// DisclosureStatus classifier unit test — ANVIL-FREE, pure computation.
//
// The conformance scenario can only reach the pass and "mismatch" statuses
// (§6b v2 removed plain disburse(), and the honest leg publishes in full), so
// the classifier's "unverifiable"/"withheld" branches — and the branch ORDERING
// that keeps a hash-matching receiver-only publish off the alarm channel — are
// pinned here, where a synthetic ciphertext list costs nothing.
//
//   node --import tsx test/disclosure.test.ts   # (== npm run test:disclosure)

import { disclosureChain } from "@bongtu/sdk/envelope";
import { verifyDisclosure } from "../src/disclosure.js";

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

console.log(`\n${failures === 0 ? "DISCLOSURE TEST PASS — all four DisclosureStatus branches + branch ordering pinned" : `DISCLOSURE TEST FAIL — ${failures} assertion(s)`}`);
process.exit(failures === 0 ? 0 : 1);
