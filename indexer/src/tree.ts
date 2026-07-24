// The indexer's tree state as ONE deep module (SPEC §5.1, §6b).
//
// The on-chain BongtuPool tree has three off-chain representations the indexer
// needs kept mutually consistent:
//   1. the frontier mirror (root / nextLeafIndex) — an SDK `ImtTree`, the SAME
//      class the contract's Foundry differential test pins against;
//   2. the per-leaf value records a merkle path is folded from;
//   3. the per-block batch subtree roots a single-append leaf's path folds
//      THROUGH (a disburse's underlying leaves are not chain-recoverable).
//
// `MirrorTree` WRAPS the SDK `ImtTree` (unchanged) and owns (2) + (3) + the path
// builder, so the "drive the mirror AND record the leaf AND tag the batch"
// discipline that ingest used to spread across mirror + Store + paths.ts is now
// internal to one object. Ingest speaks only the event-application language
// (applyAppend / applyAttach / recordLeaf); nothing else touches tree internals.
//
// The two low-level tree events are the authoritative drivers, each carrying the
// resulting on-chain root so the mirror is asserted per-insert (stronger than the
// "at HEAD" floor):
//   Appended(leafIndex, leaf, root)               -> applyAppend
//   SubtreeAppended(startLeafIndex, subRoot, root) -> applyAttach
// Both are replay-idempotent: an insert already below the frontier was applied by
// an earlier (partially failed) ingest call and is skipped, so the poll loop can
// retry the same log range without double-applying.

import { ImtTree } from "../../sdk/src/imt.js";
import { poseidon2 } from "../../sdk/src/poseidon.js";

/** A merkle authentication path against the current root. */
export interface PathResult {
  siblings: bigint[];
  pathIndices: number[];
  root: bigint;
}
/** Sentinel: the leaf sits inside a disburse batch (siblings not chain-recoverable). */
export interface BatchLeaf {
  batchLeaf: true;
}

export class MirrorTree {
  // The wrapped SDK frontier tree: the sole authority for root + nextLeafIndex.
  private readonly tree: ImtTree;
  readonly H: number;
  readonly B: number;
  readonly LOG_B: number;

  // Per-leaf values a merkle path is reconstructed from. `undefined` = a slot
  // never given a value: an unfilled pad slot OR a batch-interior hole (both fold
  // as 0). Real single-append leaves are written by recordLeaf (pass 2).
  private readonly leaves: (bigint | undefined)[] = [];
  // batchRoots[block] = a disburse subtree root, block = startLeafIndex / B. A
  // block is EITHER one batch subtree OR all single-append/pad leaves, never
  // mixed (a disburse pads to a B boundary before attaching, §5.1), so this
  // cleanly tags which block-level nodes are opaque batches.
  private readonly batchRoots: (bigint | undefined)[] = [];
  // zeros[k] = the value of an all-empty subtree of height k (memoised).
  private readonly zeros: bigint[];

  constructor(height: number, batchSize: number) {
    this.tree = new ImtTree(height, batchSize);
    this.H = this.tree.H;
    this.B = this.tree.B;
    this.LOG_B = this.tree.LOG_B;
    this.zeros = new Array(this.H + 1);
    this.zeros[0] = 0n;
    for (let k = 1; k <= this.H; k++) this.zeros[k] = poseidon2(this.zeros[k - 1], this.zeros[k - 1]);
  }

  /** Frontier root of the wrapped mirror (== on-chain root after every insert). */
  root(): bigint {
    return this.tree.getRoot();
  }

  /** Next free leaf index of the wrapped mirror. */
  nextLeafIndex(): number {
    return this.tree.getNextLeafIndex();
  }

  /**
   * Drive an `Appended` event: insert `leaf`, then assert the event-carried index
   * and root. Replay-safe — an insert already below the frontier is skipped.
   */
  applyAppend(leafIndex: number, leaf: bigint, root: bigint): void {
    if (leafIndex < this.tree.getNextLeafIndex()) return; // replayed insert
    this.tree.appendLeaf(leaf);
    if (this.tree.getNextLeafIndex() - 1 !== leafIndex) {
      throw new Error(`MirrorTree.applyAppend: leafIndex ${leafIndex} != mirror index ${this.tree.getNextLeafIndex() - 1}`);
    }
    if (this.tree.getRoot() !== root) {
      throw new Error(`MirrorTree.applyAppend: mirror root diverged after Appended @leaf ${leafIndex}`);
    }
  }

  /**
   * Drive a `SubtreeAppended` event: pad to the batch boundary + attach
   * `subtreeRoot` (batch leaves not chain-recoverable → holes), assert the
   * event-carried attach point and root, and tag the block as a batch. Replay
   * skips the mirror mutation but re-tags idempotently (same values).
   */
  applyAttach(startLeafIndex: number, subtreeRoot: bigint, root: bigint): void {
    if (startLeafIndex >= this.tree.getNextLeafIndex()) {
      this.tree.attachSubtree(subtreeRoot, null);
      if (this.tree.getNextLeafIndex() !== startLeafIndex + this.B) {
        throw new Error(`MirrorTree.applyAttach: start ${startLeafIndex} != mirror attach point ${this.tree.getNextLeafIndex() - this.B}`);
      }
      if (this.tree.getRoot() !== root) {
        throw new Error(`MirrorTree.applyAttach: mirror root diverged after SubtreeAppended @start ${startLeafIndex}`);
      }
    }
    // The subtree root is the block-level node a single-append leaf's path folds
    // THROUGH, so /path stays servable despite the opaque batch leaves. The B
    // slots stay holes (a path INTO the batch returns the sentinel, not a wrong
    // path). Recorded unconditionally so a replay re-tags to the same values.
    for (let k = 0; k < this.B; k++) this.leaves[startLeafIndex + k] = undefined;
    this.batchRoots[startLeafIndex / this.B] = subtreeRoot;
  }

  /** Record a real single-append leaf value (pass 2), the source a path folds from. */
  recordLeaf(leafIndex: number, leaf: bigint): void {
    this.leaves[leafIndex] = leaf;
  }

  /**
   * Record the B real underlying leaves of a disburse batch. Currently UNUSED: a
   * plain disburse only publishes the subtree root, so ingest never has these.
   * Wired for a future arbiter-mode unit that trial-decrypts the authority
   * envelope and can then serve within-batch paths — at which point path() would
   * fold the block from these leaves instead of returning the sentinel. Until
   * that unit lands, path() still tags the block a batch (via batchRoots) and
   * returns the sentinel, so filling the leaves here is observationally inert.
   */
  fillBatch(startLeafIndex: number, leaves: bigint[]): void {
    for (let k = 0; k < leaves.length; k++) this.leaves[startLeafIndex + k] = leaves[k];
  }

  /**
   * Merkle path of `leafIndex` against the current root, or the BatchLeaf
   * sentinel if the leaf sits inside a disburse batch. The path is reconstructed
   * from block-level nodes: block k is EITHER a batch (node = subtreeRoot[k],
   * leaves opaque) OR all single-append/pad leaves (node = fold of the known
   * leaves, unfilled slots = 0). Phase A folds within the leaf's own block
   * (levels 0..LOG_B-1); phase B folds over the block-node array
   * (levels LOG_B..H-1). The reconstructed root is asserted to equal root() — the
   * builder folds independently from the leaf records, so a divergence means those
   * records are corrupt (the per-insert asserts make this unreachable in practice,
   * which is why the caller needs no separate root-agreement guard).
   */
  path(leafIndex: number): PathResult | BatchLeaf {
    const B = this.B;
    const LOG_B = this.LOG_B;
    const nli = this.nextLeafIndex();
    const block = Math.floor(leafIndex / B);
    if (this.batchRoots[block] !== undefined) return { batchLeaf: true };

    const siblings: bigint[] = new Array(this.H);
    const pathIndices: number[] = new Array(this.H);

    // Phase A — within the leaf's own block (levels 0..LOG_B-1).
    let level: bigint[] = new Array(B);
    for (let i = 0; i < B; i++) level[i] = this.leafValue(block * B + i);
    // % 2 + Math.floor, never JS bitwise: ToInt32 corrupts indices >= 2^31.
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
    const numBlocks = Math.ceil(nli / B);
    let arr: bigint[] = new Array(numBlocks);
    for (let k = 0; k < numBlocks; k++) arr[k] = this.blockNode(k);
    let bidx = block;
    for (let j = 0; j < this.H - LOG_B; j++) {
      const lvl = LOG_B + j;
      const bit = bidx % 2;
      pathIndices[lvl] = bit;
      if (bit === 1) {
        siblings[lvl] = arr[bidx - 1];
      } else {
        siblings[lvl] = bidx + 1 < arr.length ? arr[bidx + 1] : this.zeros[lvl];
      }
      const nx: bigint[] = new Array(Math.ceil(arr.length / 2));
      for (let m = 0; m < nx.length; m++) {
        const left = arr[2 * m];
        const right = 2 * m + 1 < arr.length ? arr[2 * m + 1] : this.zeros[lvl];
        nx[m] = poseidon2(left, right);
      }
      arr = nx;
      bidx = Math.floor(bidx / 2);
    }

    const reRoot = arr[0];
    if (reRoot !== this.root()) {
      throw new Error(`MirrorTree.path: reconstructed root diverged from mirror @leaf ${leafIndex}`);
    }
    return { siblings, pathIndices, root: reRoot };
  }

  /** Leaf value at `idx` in a NON-batch block: recorded → its value, else 0 (pad). */
  private leafValue(idx: number): bigint {
    const v = this.leaves[idx];
    return v === undefined ? 0n : v;
  }

  /** Block-level node for block k: batch subtree root, else fold of its leaves. */
  private blockNode(k: number): bigint {
    const batch = this.batchRoots[k];
    if (batch !== undefined) return batch;
    let level: bigint[] = new Array(this.B);
    for (let i = 0; i < this.B; i++) level[i] = this.leafValue(k * this.B + i);
    for (let d = 0; d < this.LOG_B; d++) {
      const next: bigint[] = new Array(level.length / 2);
      for (let m = 0; m < next.length; m++) next[m] = poseidon2(level[2 * m], level[2 * m + 1]);
      level = next;
    }
    return level[0];
  }
}
