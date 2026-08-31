// MirrorTree unit test (SPEC §5.1, §6b) — ANVIL-FREE, pure computation.
//
// Drives MirrorTree with a hand-built event sequence (single appends + batch
// attaches, including two partial-block pads and one already-aligned batch) and
// checks, at EVERY step, that root() equals the independent SDK ground truth
// `ImtTree.naiveRoot` over the same dense leaf multiset. The test itself plays the
// role of the chain: it maintains the dense multiset (real leaves + dead pad
// zeros + batch leaves), derives each event's carried root from naiveRoot, and
// feeds it in — so applyAppend/applyAttach's own per-insert root asserts are also
// exercised (a wrong carried root throws).
//
// Then: a replayed event (index already below the frontier) is idempotent;
// path() of a single-append leaf folds back to root(); path() of a batch-interior
// leaf returns the sentinel.
//
//   node --import tsx test/tree.test.ts        # (== npm run test:tree)

import { poseidon2 } from "@bongtu/core/poseidon";
import { ImtTree } from "@bongtu/core/imt";
import { MirrorTree } from "../src/tree.js";

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

function foldToRoot(leaf: bigint, siblings: bigint[], pathIndices: number[]): bigint {
  return siblings.reduce<bigint>(
    (cur, sibling, j) => (pathIndices[j] === 1 ? poseidon2(sibling, cur) : poseidon2(cur, sibling)),
    leaf,
  );
}

const H = 8;
const B = 4; // LOG_B = 2

const mt = new MirrorTree(H, B);
const ref = new ImtTree(H, B); // stateless computeSubtreeRoot source
const dense: bigint[] = []; // the dense leaf multiset naiveRoot is taken over

// After each op: mt must agree with the independent dense recompute, both in root
// and frontier position. This is the per-step invariant the whole test rests on.
function expectAgree(label: string): void {
  const nr = ImtTree.naiveRoot(dense, H);
  ok(mt.root() === nr, `${label}: root() == naiveRoot(dense)`);
  ok(mt.nextLeafIndex() === dense.length, `${label}: nextLeafIndex() == dense length (${dense.length})`);
}

function doAppend(v: bigint, label: string): number {
  const leafIndex = dense.length;
  dense.push(v);
  // pass 1 drives the frontier; pass 2 records the leaf value path() folds from —
  // exactly the two writes ingest performs per single-append leaf.
  mt.applyAppend(leafIndex, v, ImtTree.naiveRoot(dense, H));
  mt.recordLeaf(leafIndex, v);
  expectAgree(label);
  return leafIndex;
}

function doBatch(leaves: bigint[], label: string): { start: number; subtreeRoot: bigint } {
  while (dense.length % B !== 0) dense.push(0n); // partial-block pad: dead zero leaves
  const start = dense.length;
  const subtreeRoot = ref.computeSubtreeRoot(leaves);
  for (const k of Array(B).keys()) dense.push(k < leaves.length ? leaves[k] : 0n);
  mt.applyAttach(start, subtreeRoot, ImtTree.naiveRoot(dense, H));
  expectAgree(label);
  return { start, subtreeRoot };
}

step("DRIVE: single appends + batch attaches (2 partial-block pads + 1 aligned batch)");
const li0 = doAppend(10n, "append @0");
doAppend(20n, "append @1");
doAppend(30n, "append @2"); // block 0 now 3/4 full → next batch must pad slot 3
const bA = doBatch([100n, 101n, 102n, 103n], "batchA @4 (pads 1 dead slot)");
const li8 = doAppend(40n, "append @8");
doAppend(50n, "append @9"); // block 2 now 2/4 → next batch pads 2 dead slots
const bB = doBatch([200n, 201n, 202n, 203n], "batchB @12 (pads 2 dead slots)");
const bC = doBatch([300n, 301n, 302n, 303n], "batchC @16 (already aligned, no pad)");
const li20 = doAppend(60n, "append @20");
doAppend(70n, "append @21");

ok(bA.start === 4 && bB.start === 12 && bC.start === 16, `batch starts 4/12/16 (got ${bA.start}/${bB.start}/${bC.start})`);

const rootFinal = mt.root();
const nliFinal = mt.nextLeafIndex();

// (idempotency) A replayed event whose index is already below the frontier must
// not mutate state. applyAppend short-circuits before touching the mirror; the
// carried root is deliberately bogus to prove it is never re-checked. applyAttach
// re-tags the batch (same subtreeRoot) without re-attaching.
step("REPLAY: an already-applied event is idempotent");
mt.applyAppend(li0, 10n, 999999n); // leafIndex 0 << frontier → no-op
mt.applyAttach(bA.start, bA.subtreeRoot, 999999n); // start 4 << frontier → re-tag only
ok(mt.root() === rootFinal, "replayed append+attach leave root() unchanged");
ok(mt.nextLeafIndex() === nliFinal, "replayed append+attach leave nextLeafIndex() unchanged");
expectAgree("post-replay still agrees with naiveRoot");

// (path folds) A single-append leaf's path, folded with its value, reproduces the
// head root — through a normal block (li0), through a block that sits AFTER two
// batches (li8/li20 fold through batch subtreeRoots at the block level).
step("PATH: single-append leaf folds to root(); pad leaf folds too");
for (const [idx, val] of [[li0, 10n], [li8, 40n], [li20, 60n], [3, 0n]] as [number, bigint][]) {
  const p = mt.path(idx);
  ok(!("batchLeaf" in p), `path(${idx}) is a real path, not the batch sentinel`);
  if ("batchLeaf" in p) continue;
  ok(p.siblings.length === H && p.pathIndices.length === H, `path(${idx}) has H=${H} siblings + indices`);
  ok(p.root === rootFinal, `path(${idx}).root == head root`);
  ok(foldToRoot(val, p.siblings, p.pathIndices) === rootFinal, `path(${idx}) folds value ${val} to head root`);
}

// (batch sentinel) A leaf INSIDE a disburse batch has no chain-recoverable
// siblings (only the subtree root was emitted) → the sentinel, one per batch.
step("PATH: batch-interior leaf returns the sentinel");
for (const idx of [bA.start + 1, bB.start + 2, bC.start]) {
  const p = mt.path(idx);
  ok("batchLeaf" in p && p.batchLeaf === true, `path(${idx}) (batch interior) → { batchLeaf: true }`);
}

// (per-insert assert is live) A wrong carried root on a fresh, un-replayed insert
// throws — this is the guard that lets /path drop its old root-agreement 500.
step("GUARD: applyAppend with a wrong event root throws");
{
  const neg = new MirrorTree(H, B);
  neg.applyAppend(0, 10n, ImtTree.naiveRoot([10n], H)); // honest first insert
  const threw = ((): boolean => {
    try {
      neg.applyAppend(1, 20n, 12345n); // wrong carried root
      return false;
    } catch {
      return true;
    }
  })();
  ok(threw, "applyAppend rejects a diverging carried root");
}

console.log(`\n${failures.count === 0 ? "MIRRORTREE TEST PASS — root()==naiveRoot each step, replay idempotent, paths fold, batch sentinel" : `MIRRORTREE TEST FAIL — ${failures.count} assertion(s)`}`);
process.exit(failures.count === 0 ? 0 : 1);
