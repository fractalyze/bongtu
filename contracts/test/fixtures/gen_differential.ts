// Differential-test oracle (SPEC §5.1, M0 Done#3-i).
//
// Drives the U1 ImtTree reference through the mandated interleaved sequence
//   deposit(2) -> transfer(2) -> disburse(pad+attach 16) -> withdraw(1)
// and emits, for the Foundry differential test, every leaf/subtreeRoot the
// contract must insert AND the reference root AFTER EVERY (real) insert. The
// contract's Appended/SubtreeAppended event roots are compared 1:1 against
// `roots` here; if the on-chain single-frontier IMT diverges from this oracle
// at any insert, the test fails.
//
// Batch size B = 16 (LOG_B = 4), height 32 — the M0 disburse arity.
//
//   npx tsx gen_differential.ts   # writes differential.json

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";
import { commitment, deriveKeypair } from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";

const HERE = dirname(fileURLToPath(import.meta.url));
const H = 32;
const B = 16;

const recv = (i: number): Point => deriveKeypair(2000000011n + BigInt(i) * 7654321n).publicKey;
const commit = (value: bigint | number, i: number): bigint =>
  commitment(BigInt(value), 500000n + BigInt(i), recv(i));

// Deterministic, distinct leaf commitments for each stage.
const deposit = [commit(1000, 0), commit(2000, 1)];
const transfer = [commit(600, 2), commit(400, 3)];
const batch = Array.from({ length: B }, (_, i) => commit(100, 10 + i)); // 16-leaf disburse subtree
const withdrawChange = commit(50, 40);

const tree = new ImtTree(H, B);
const roots: bigint[] = []; // reference root AFTER each real insert, in event order

// deposit(2): two single-leaf appends
tree.appendLeaf(deposit[0]);
roots.push(tree.getRoot());
tree.appendLeaf(deposit[1]);
roots.push(tree.getRoot());

// transfer(2): two single-leaf appends
tree.appendLeaf(transfer[0]);
roots.push(tree.getRoot());
tree.appendLeaf(transfer[1]);
roots.push(tree.getRoot());

// disburse: pad to a B boundary + attach the 16-leaf subtree root (one observable insert)
const subtreeRoot = tree.computeSubtreeRoot(batch);
const rootBeforeAttach = tree.getRoot();
tree.attachSubtree(subtreeRoot, batch);
roots.push(tree.getRoot());

// withdraw(1): one single-leaf append (change output)
tree.appendLeaf(withdrawChange);
roots.push(tree.getRoot());

const s = (x: bigint): string => "0x" + BigInt(x).toString(16).padStart(64, "0");
const out = {
  height: H,
  batchSize: B,
  deposit: deposit.map(s),
  transfer: transfer.map(s),
  batch: batch.map(s),
  subtreeRoot: s(subtreeRoot),
  withdrawChange: s(withdrawChange),
  // sanity: padding a partial block must NOT change the root
  rootBeforeAttach: s(rootBeforeAttach),
  finalNextLeafIndex: tree.getNextLeafIndex(),
  roots: roots.map(s), // [R_d0, R_d1, R_t0, R_t1, R_disburse, R_withdraw]
};

mkdirSync(HERE, { recursive: true });
writeFileSync(join(HERE, "differential.json"), JSON.stringify(out, null, 2));
console.log("wrote differential.json; roots after each insert:");
out.roots.forEach((r, i) => console.log(`  [${i}] ${r}`));
// deposit(2) + transfer(2) + disburse pad(4->16)+attach(16)=32 + withdraw(1) = 33
console.log(`finalNextLeafIndex = ${out.finalNextLeafIndex} (expect 33)`);
