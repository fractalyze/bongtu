// Merkle-path builder over ingested tree state (SPEC §6b `/path`, §5.1).
//
// The SDK `ImtTree.merklePath` re-folds a DENSE leaf array, so it cannot serve a
// path once a disburse batch is present (the batch leaves are chain-unknown =
// holes, and one hole aborts the whole reconstruction). The contract's frontier
// tree does not need those leaves: a single-append leaf's path passes THROUGH a
// batch region only at that region's block-level node, which is exactly the
// batch's `subtreeRoot` (emitted on-chain). This builder reproduces the contract
// tree from block-level nodes:
//
//   block k (B leaves) is EITHER a batch (node = subtreeRoot[k], leaves opaque)
//   OR all single-append/pad leaves (node = fold of the known leaves, unfilled
//   slots = 0). A disburse always pads to a B boundary before attaching (§5.1),
//   so a block is never mixed — the tag is unambiguous.
//
// Path for a leaf in a NORMAL block = within-block siblings (levels 0..LOG_B-1,
// from the block's known leaves) ++ block-level siblings (levels LOG_B..H-1, over
// the block-node array with zeros[LOG_B..] filler). A leaf inside a batch block
// has no chain-recoverable siblings → BatchLeaf (the API answers 422).

import { poseidon2 } from "../../sdk/src/poseidon.js";
import type { Store } from "./store.js";

export interface PathResult {
  siblings: bigint[];
  pathIndices: number[];
  root: bigint;
}
export interface BatchLeaf {
  batchLeaf: true;
}

function zerosLadder(H: number): bigint[] {
  const z = new Array<bigint>(H + 1);
  z[0] = 0n;
  for (let k = 1; k <= H; k++) z[k] = poseidon2(z[k - 1], z[k - 1]);
  return z;
}

/** Leaf value at `idx` in a NON-batch block: known → its value, unfilled → 0. */
function normalLeaf(store: Store, idx: number): bigint {
  const rec = store.getLeaf(idx);
  if (rec === undefined || rec.leaf === null) return 0n; // dead-zero pad slot
  return BigInt(rec.leaf);
}

/** The block-level node for block k: batch subtree root, else fold of its leaves. */
function blockNode(store: Store, k: number, B: number, LOG_B: number): bigint {
  const batch = store.getBatchRoot(k);
  if (batch !== undefined) return batch;
  let level: bigint[] = new Array(B);
  for (let i = 0; i < B; i++) level[i] = normalLeaf(store, k * B + i);
  for (let d = 0; d < LOG_B; d++) {
    const next: bigint[] = new Array(level.length / 2);
    for (let m = 0; m < next.length; m++) next[m] = poseidon2(level[2 * m], level[2 * m + 1]);
    level = next;
  }
  return level[0];
}

/**
 * Merkle path of `leafIndex` against the current tree, or BatchLeaf if the leaf
 * sits inside a disburse batch (siblings not chain-recoverable). Folding the leaf
 * up with the returned siblings reproduces the contract root.
 */
export function buildPath(
  store: Store,
  leafIndex: number,
  nextLeafIndex: number,
  H: number,
  B: number,
): PathResult | BatchLeaf {
  const LOG_B = Math.round(Math.log2(B));
  const z = zerosLadder(H);
  const block = Math.floor(leafIndex / B);
  if (store.getBatchRoot(block) !== undefined) return { batchLeaf: true };

  const siblings: bigint[] = new Array(H);
  const pathIndices: number[] = new Array(H);

  // Phase A — within the leaf's own block (levels 0..LOG_B-1).
  let level: bigint[] = new Array(B);
  for (let i = 0; i < B; i++) level[i] = normalLeaf(store, block * B + i);
  // % 2 + Math.floor, never JS bitwise: ToInt32 corrupts indices >= 2^31 (imt.ts convention).
  let idx = leafIndex % B;
  for (let j = 0; j < LOG_B; j++) {
    const bit = idx % 2;
    pathIndices[j] = bit;
    siblings[j] = level[bit === 1 ? idx - 1 : idx + 1];
    const next: bigint[] = new Array(level.length / 2);
    for (let m = 0; m < next.length; m++) next[m] = poseidon2(level[2 * m], level[2 * m + 1]);
    level = next;
    idx = Math.floor(idx / 2);
  }

  // Phase B — block-level (levels LOG_B..H-1) over the block-node array.
  const numBlocks = Math.ceil(nextLeafIndex / B);
  let arr: bigint[] = new Array(numBlocks);
  for (let k = 0; k < numBlocks; k++) arr[k] = blockNode(store, k, B, LOG_B);
  let bidx = block;
  for (let j = 0; j < H - LOG_B; j++) {
    const lvl = LOG_B + j;
    const bit = bidx % 2;
    pathIndices[lvl] = bit;
    if (bit === 1) {
      siblings[lvl] = arr[bidx - 1];
    } else {
      siblings[lvl] = bidx + 1 < arr.length ? arr[bidx + 1] : z[lvl];
    }
    const next: bigint[] = new Array(Math.ceil(arr.length / 2));
    for (let m = 0; m < next.length; m++) {
      const left = arr[2 * m];
      const right = 2 * m + 1 < arr.length ? arr[2 * m + 1] : z[lvl];
      next[m] = poseidon2(left, right);
    }
    arr = next;
    bidx = Math.floor(bidx / 2);
  }

  return { siblings, pathIndices, root: arr[0] };
}
