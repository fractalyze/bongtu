// Unified single-frontier Incremental Merkle Tree (SPEC §5.1).
//
// This is the OFF-CHAIN ORACLE for the on-chain BongtuPool IMT: the U3 Foundry
// differential test asserts `contract.root === ImtTree.getRoot()` across an
// interleaved deposit/transfer/disburse/withdraw sequence. If this reference is
// wrong, every later differential test is meaningless — so correctness beats
// cleverness here, and every observable (root, frontier) is cross-checked against
// the independent `naiveRoot` dense recompute in the test suite.
//
// One height-H tree holds BOTH incremental single-leaf inserts (transfer /
// withdraw / deposit outputs) AND B-leaf batch subtrees (disburse), sharing one
// `nextLeafIndex` counter and one `filledSubtrees` frontier, so a batch-inserted
// note is spendable against the same root as a single-inserted one.
//
// Conventions:
//  - Field elements are native BigInt throughout.
//  - Leaf/level indices are plain Numbers (capacity 2^32 << 2^53) and we use
//    Math arithmetic, never JS bitwise ops (which are 32-bit and would corrupt
//    indices >= 2^31).
//  - Left/right order at level j is bit j of the index: bit 0 => left child.
//    This matches circomlib's CheckIMTProof (Num2Bits + Switcher) exactly.

import { poseidon2 } from "./poseidon.js";

// A field element in a form the tree accepts as leaf input (coerced via BigInt).
// Declared once in babyjub.ts; re-exported so `@bongtu/core/imt` importers keep working.
import type { FieldInput } from "./babyjub.js";
export type { FieldInput } from "./babyjub.js";

// A reconstructed merkle authentication path against the current root.
export interface MerklePath {
  siblings: bigint[];
  pathIndices: number[];
}

export class ImtTree {
  readonly H: number;
  readonly B: number;
  readonly LOG_B: number;
  readonly zeros: bigint[];
  readonly filledSubtrees: bigint[];
  nextLeafIndex: number;
  root: bigint;
  // Dense leaf record; `undefined` marks a hole (batch attached without leaves).
  readonly leaves: (bigint | undefined)[];

  // height = number of levels above the leaves (default 32). batchSize B must be
  // a power of two <= 2^height; LOG_B = log2(B) is the level at which a disburse
  // subtree root is attached.
  constructor(height = 32, batchSize = 16) {
    if (!Number.isInteger(height) || height < 1) {
      throw new Error(`ImtTree: height must be a positive integer, got ${height}`);
    }
    if (!isPowerOfTwo(batchSize)) {
      throw new Error(`ImtTree: batchSize must be a power of two, got ${batchSize}`);
    }
    this.H = height;
    this.B = batchSize;
    this.LOG_B = Math.round(Math.log2(batchSize));
    if (this.LOG_B > this.H) {
      throw new Error(`ImtTree: LOG_B (${this.LOG_B}) exceeds height (${this.H})`);
    }

    // zeros[k] = the value of an all-empty subtree of height k.
    // zeros[0] = 0, zeros[k] = H(zeros[k-1], zeros[k-1]).
    this.zeros = new Array(this.H + 1);
    this.zeros[0] = 0n;
    for (let k = 1; k <= this.H; k++) {
      this.zeros[k] = poseidon2(this.zeros[k - 1], this.zeros[k - 1]);
    }

    // filledSubtrees[i] = the left-sibling hash waiting at level i on the current
    // insertion path (Tornado frontier). Initially every level is empty.
    this.filledSubtrees = new Array(this.H);
    for (let i = 0; i < this.H; i++) {
      this.filledSubtrees[i] = this.zeros[i];
    }

    this.nextLeafIndex = 0;
    this.root = this.zeros[this.H];

    // Dense record of every leaf actually placed (real outputs, dead-zero padding,
    // and — when supplied — the individual leaves of an attached batch). Only used
    // to reconstruct arbitrary merkle paths; the root/frontier never read it.
    this.leaves = [];
  }

  getRoot(): bigint {
    return this.root;
  }

  getNextLeafIndex(): number {
    return this.nextLeafIndex;
  }

  // Standard Tornado single-leaf insert at nextLeafIndex: fold the new leaf up the
  // frontier (empty right-siblings = zeros[i]), update filledSubtrees + root,
  // nextLeafIndex += 1. Used for deposit/transfer/withdraw outputs.
  appendLeaf(commitment: FieldInput): void {
    const leaf = BigInt(commitment);
    this.leaves[this.nextLeafIndex] = leaf;
    this._insertNode(leaf, 0);
  }

  // Append a complete B-leaf subtree (disburse). SPEC §5.1:
  //   1. pad nextLeafIndex up to a multiple of B — the pending partial block's
  //      remaining slots become permanently-dead zero leaves;
  //   2. place `subtreeRoot` as the node at level LOG_B, position nextLeafIndex/B,
  //      and propagate to the root; nextLeafIndex += B.
  // `leaves` (optional) are the B underlying commitments: when supplied they are
  // recorded so U4 can produce merkle paths INTO the batch, and subtreeRoot is
  // validated against computeSubtreeRoot(leaves). The root is computed from
  // subtreeRoot alone regardless, exactly as the contract does.
  attachSubtree(subtreeRoot: FieldInput, leaves: FieldInput[] | null = null): void {
    const rootNode = BigInt(subtreeRoot);

    // Validate BEFORE mutating any tree state. A rejected attach must leave the
    // tree untouched: on-chain the whole tx reverts and the tree advances
    // nothing, so the oracle must not pad/advance on the error path either
    // (otherwise a caught throw shifts every later index and diverges the root).
    // computeSubtreeRoot is pure, so this is safe to run pre-pad.
    if (leaves !== null && leaves.length > this.B) {
      throw new Error(`attachSubtree: ${leaves.length} leaves exceeds batchSize ${this.B}`);
    }
    if (leaves !== null && this.computeSubtreeRoot(leaves) !== rootNode) {
      throw new Error("attachSubtree: subtreeRoot does not match computeSubtreeRoot(leaves)");
    }

    this._padToBlockBoundary();
    const blockStart = this.nextLeafIndex; // now a multiple of B

    if (leaves !== null) {
      for (let k = 0; k < this.B; k++) {
        this.leaves[blockStart + k] = k < leaves.length ? BigInt(leaves[k]) : this.zeros[0];
      }
    } else {
      // Leaves unknown: mark the block's slots as holes so a later merklePath into
      // the batch fails loudly instead of returning a wrong (non-verifying) path.
      for (let k = 0; k < this.B; k++) {
        this.leaves[blockStart + k] = undefined;
      }
    }

    this._insertNode(rootNode, this.LOG_B);
  }

  // Build the depth-LOG_B balanced Poseidon(2) tree over exactly B commitments
  // (pad with zeros[0] if fewer) and return its root. Mirrors the in-circuit
  // subtree gadget so U3/U4 can cross-check the disburse subtreeRoot.
  computeSubtreeRoot(commitments: FieldInput[]): bigint {
    if (commitments.length > this.B) {
      throw new Error(`computeSubtreeRoot: ${commitments.length} leaves exceeds batchSize ${this.B}`);
    }
    let level: bigint[] = new Array(this.B);
    for (let k = 0; k < this.B; k++) {
      level[k] = k < commitments.length ? BigInt(commitments[k]) : this.zeros[0];
    }
    for (let depth = 0; depth < this.LOG_B; depth++) {
      const next: bigint[] = new Array(level.length / 2);
      for (let j = 0; j < next.length; j++) {
        next[j] = poseidon2(level[2 * j], level[2 * j + 1]);
      }
      level = next;
    }
    return level[0];
  }

  // Merkle path of a previously-inserted real leaf against the CURRENT root:
  // { siblings[H], pathIndices[H] }, pathIndices[j] = bit j of leafIndex.
  // Reconstructed from the dense leaf record (same zeros + pairing as the root),
  // so folding the leaf back up with these siblings reproduces getRoot().
  merklePath(leafIndex: number): MerklePath {
    if (!Number.isInteger(leafIndex) || leafIndex < 0 || leafIndex >= this.nextLeafIndex) {
      throw new Error(`merklePath: leafIndex ${leafIndex} out of range [0, ${this.nextLeafIndex})`);
    }
    for (let i = 0; i < this.nextLeafIndex; i++) {
      if (this.leaves[i] === undefined) {
        throw new Error(
          `merklePath: leaf ${i} not recorded (a batch was attached without its leaves); ` +
            "pass the batch leaves to attachSubtree to enable merkle paths",
        );
      }
    }

    const siblings: bigint[] = new Array(this.H);
    const pathIndices: number[] = new Array(this.H);
    // Past the undefined guard above, every entry in [0, nextLeafIndex) is a bigint.
    let level: bigint[] = this.leaves.slice(0, this.nextLeafIndex) as bigint[];
    let idx = leafIndex;
    for (let j = 0; j < this.H; j++) {
      const bit = idx % 2;
      pathIndices[j] = bit;
      const siblingIndex = bit === 1 ? idx - 1 : idx + 1;
      siblings[j] = siblingIndex < level.length ? level[siblingIndex] : this.zeros[j];

      const next: bigint[] = new Array(Math.ceil(level.length / 2));
      for (let k = 0; k < next.length; k++) {
        const left = level[2 * k];
        const right = 2 * k + 1 < level.length ? level[2 * k + 1] : this.zeros[j];
        next[k] = poseidon2(left, right);
      }
      level = next;
      idx = Math.floor(idx / 2);
    }
    return { siblings, pathIndices };
  }

  // Independent ground truth: full height-H root of a DENSE leaf array (positions
  // beyond `leaves.length`, and any odd tails, are zeros). Recomputed from scratch
  // with no frontier state — this is what getRoot() must equal after every insert.
  // Static so the test can call it without touching tree state.
  static naiveRoot(leaves: (FieldInput | undefined)[], height: number): bigint {
    const zeros: bigint[] = new Array(height + 1);
    zeros[0] = 0n;
    for (let k = 1; k <= height; k++) {
      zeros[k] = poseidon2(zeros[k - 1], zeros[k - 1]);
    }
    if (leaves.length === 0) {
      return zeros[height];
    }
    let level: bigint[] = leaves.map((x) => (x === undefined ? 0n : BigInt(x)));
    for (let j = 0; j < height; j++) {
      const next: bigint[] = new Array(Math.ceil(level.length / 2));
      for (let k = 0; k < next.length; k++) {
        const left = level[2 * k];
        const right = 2 * k + 1 < level.length ? level[2 * k + 1] : zeros[j];
        next[k] = poseidon2(left, right);
      }
      level = next;
    }
    return level[0];
  }

  // --- internals ------------------------------------------------------------

  // Fold `node` (sitting at level `startLevel`, position nextLeafIndex/2^startLevel)
  // up to the root, updating filledSubtrees[startLevel..H-1] + root, then advance
  // nextLeafIndex by 2^startLevel. Shared by appendLeaf (startLevel 0) and
  // attachSubtree (startLevel LOG_B). Requires nextLeafIndex aligned to 2^startLevel.
  _insertNode(node: bigint, startLevel: number): void {
    const stride = 2 ** startLevel;
    if (this.nextLeafIndex % stride !== 0) {
      throw new Error(`_insertNode: nextLeafIndex ${this.nextLeafIndex} not aligned to 2^${startLevel}`);
    }
    if (this.nextLeafIndex + stride > 2 ** this.H) {
      throw new Error("_insertNode: tree is full");
    }

    let currentIndex = Math.floor(this.nextLeafIndex / stride);
    let current = node;
    for (let i = startLevel; i < this.H; i++) {
      let left: bigint;
      let right: bigint;
      if (currentIndex % 2 === 0) {
        left = current;
        right = this.zeros[i];
        this.filledSubtrees[i] = current;
      } else {
        left = this.filledSubtrees[i];
        right = current;
      }
      current = poseidon2(left, right);
      currentIndex = Math.floor(currentIndex / 2);
    }
    this.root = current;
    this.nextLeafIndex += stride;
  }

  // Pad the pending partial block (if any) up to the next B-aligned boundary by
  // inserting dead zero leaves. The contract does this in <= LOG_B folds; the
  // oracle inserts the zero leaves outright — the resulting tree is identical
  // (padding with the default empty value does not change the root), and the
  // frontier is a pure function of (leaf multiset, nextLeafIndex), so this
  // produces exactly the frontier the contract will hold. Verified against
  // naiveRoot in the interleaved differential test.
  _padToBlockBoundary(): void {
    while (this.nextLeafIndex % this.B !== 0) {
      this.leaves[this.nextLeafIndex] = this.zeros[0];
      this._insertNode(this.zeros[0], 0);
    }
  }
}

// Verification counterpart of merklePath: fold `leaf` back up an authentication
// path, taking left/right at level j from bit j of leafIndex — bit == 1 means the
// sibling is the LEFT child (the header's documented convention, matching
// circomlib's CheckIMTProof exactly). merklePath's pathIndices[j] IS bit j of the
// leafIndex it was requested for, so callers pass the leafIndex they already hold
// — one fold convention, no second pathIndices flavor to flip. Pure; folds over
// siblings.length levels, so it works at any height.
// Closure property (pinned in the sdk suite): foldToRoot(leaves[i],
// merklePath(i).siblings, i) === getRoot() for every recorded leaf.
export function foldToRoot(leaf: FieldInput, siblings: FieldInput[], leafIndex: number): bigint {
  let cur = BigInt(leaf);
  let idx = leafIndex;
  for (let j = 0; j < siblings.length; j++) {
    cur = idx % 2 === 1 ? poseidon2(siblings[j], cur) : poseidon2(cur, siblings[j]);
    idx = Math.floor(idx / 2);
  }
  return cur;
}

function isPowerOfTwo(n: number): boolean {
  // Math-based, not `n & (n-1)`: bitwise ops truncate to int32 and would misjudge
  // index-scale values >= 2^31, which this module forbids (see header). log2 of a
  // power of two is exactly integer for n <= 2^52.
  return Number.isInteger(n) && n >= 1 && Number.isInteger(Math.log2(n));
}
