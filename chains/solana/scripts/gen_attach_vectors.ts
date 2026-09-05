// gen_attach_vectors.ts — differential vectors for `Frontier::attach_subtree`
// (SOLR §4.1), the close-loop branch coverage the single rem=1 disburse
// fixture cannot give. Every case is derived from the packages/core ImtTree
// oracle at the enterprise profile (H=32, B=256): seed `preLeaves`, attach
// one (or two) full depth-8 subtrees, record the oracle's post root and
// frontier. The rem shapes cover every close-loop branch: 0 (block-aligned —
// the empty tree AND right after a full block, so the close is skipped and
// the level-8 insert lands as a right child), 1 (the committed disburse
// fixture's shape), 0b10101011 = 171 (alternating bits — left-sibling
// filled_subtrees reads at i in {0,1,3,5,7} interleaved with zero-sibling
// folds), 255 (all eight bits — every left-sibling branch), plus one
// TWO-attach sequence (the second attach lands block-aligned on a frontier
// the first attach wrote).
//
// Run from the repo root:
//   node_modules/.bin/tsx chains/solana/scripts/gen_attach_vectors.ts
//
// Reads   packages/core (poseidon + ImtTree — the JS oracle; the enterprise
//         profile H/B/LOG_B from @bongtu/core/solana) and the shared fixture
//         assertion vocabulary (circuits/fixtures/fixture_lib.ts)
// Writes  chains/solana/conformance/attach_vectors.json (gate 7 input)
//
// postState carries the PROGRAM's expected frontier: Frontier::attach_subtree
// leaves filled_subtrees[i < LOG_B] STALE (the EVM _attachSubtree shape —
// reads them, never writes), while the oracle pads leaf-by-leaf and rewrites
// them. Both agree on the root and on every level >= LOG_B, so the sub-LOG_B
// slots are spliced from the case's pre-attach frontier (the
// gen_enterprise_vectors.ts precedent). Every case is additionally
// cross-checked against ImtTree.naiveRoot (the dense from-scratch recompute)
// before anything is written — a drifted oracle fails here, not in mollusk.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";
import { poseidon2 } from "@bongtu/core/poseidon";
import { BATCH_B_ENTERPRISE, LOG_B_ENTERPRISE, TREE_HEIGHT } from "@bongtu/core/solana";

import {
  hex32,
  makeAssertEq,
  snapshot,
  writeJson,
  type TreeSnapshot,
} from "../../../circuits/fixtures/fixture_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = join(HERE, "..", "conformance");

// Enterprise profile tree shape (gen_enterprise_vectors.ts): height 32
// protocol-wide, B=256 (the production disburse arity), LOG_B = 8.
const H = TREE_HEIGHT;
const B = BATCH_B_ENTERPRISE;
const LOG_B = LOG_B_ENTERPRISE;

const assertEq = makeAssertEq("gen_attach_vectors");

// Deterministic nonzero leaves: leaf = poseidon2(tag, k), derived through the
// same packages/core poseidon the tree folds with — byte-stable across runs,
// no RNG, and spread over the field (unlike small integers).
function makeLeaves(tag: bigint, n: number): bigint[] {
  return Array.from({ length: n }, (_, k) => {
    const leaf = poseidon2(tag, BigInt(k));
    if (leaf === 0n) throw new Error("gen_attach_vectors: poseidon produced a zero leaf");
    return leaf;
  });
}

interface AttachStep {
  subtreeLeaves: string[];
  subtreeRoot: string;
  expectedStartLeafIndex: number;
  postRoot: string;
  postState: TreeSnapshot;
}

interface AttachCase {
  name: string;
  rem: number;
  preLeaves: string[];
  preState: TreeSnapshot;
  attaches: AttachStep[];
}

function makeCase(name: string, preCount: number, attachCount: number, tag: bigint): AttachCase {
  const t = new ImtTree(H, B);
  const pre = makeLeaves(tag, preCount);
  for (const leaf of pre) t.appendLeaf(leaf);
  const preState = snapshot(t);
  assertEq(preState.nextLeafIndex % B, preCount % B, `${name} rem shape`);

  const attaches = Array.from({ length: attachCount }, (_, a): AttachStep => {
    const sub = makeLeaves(tag + BigInt(1000 + a), B);
    const subtreeRoot = t.computeSubtreeRoot(sub);
    t.attachSubtree(subtreeRoot, sub); // validates root vs leaves internally
    const post = snapshot(t);
    // Program-side splice: the attach never writes filled_subtrees[i < LOG_B]
    // (only the seeding appends did), so across the WHOLE attach sequence the
    // program's sub-LOG_B frontier stays at the case's pre-attach values.
    const postProgram = {
      ...post,
      filledSubtrees: post.filledSubtrees.map((s, i) =>
        i < LOG_B ? preState.filledSubtrees[i] : s,
      ),
    };
    return {
      subtreeLeaves: sub.map(hex32),
      subtreeRoot: hex32(subtreeRoot),
      expectedStartLeafIndex: post.nextLeafIndex - B,
      postRoot: post.currentRoot,
      postState: postProgram,
    };
  });

  // Independent dense recompute: the oracle frontier algebra is itself pinned
  // before these vectors pin the Rust port against it.
  assertEq(
    snapshot(t).currentRoot,
    hex32(ImtTree.naiveRoot(t.leaves, H)),
    `${name} naiveRoot cross-check`,
  );

  return { name, rem: preCount % B, preLeaves: pre.map(hex32), preState, attaches };
}

function main(): void {
  const cases = [
    makeCase("rem0_empty_tree", 0, 1, 11n),
    makeCase("rem0_after_full_block", 256, 1, 22n),
    makeCase("rem1", 1, 1, 33n),
    makeCase("rem171_high_set_bits", 0b10101011, 1, 44n),
    makeCase("rem255_all_bits", 255, 1, 55n),
    makeCase("rem171_two_consecutive_attaches", 0b10101011, 2, 66n),
  ];

  // The vector set is part of the contract: losing a rem shape (or the
  // two-attach sequence) silently un-covers a close-loop branch.
  const rems = new Set(cases.map((c) => c.rem));
  for (const want of [0, 1, 0b10101011, 255]) {
    if (!rems.has(want)) throw new Error(`gen_attach_vectors: missing rem=${want} coverage`);
  }
  if (!cases.some((c) => c.attaches.length === 2)) {
    throw new Error("gen_attach_vectors: missing the two-attach sequence");
  }

  const out = {
    comment:
      "GENERATED by chains/solana/scripts/gen_attach_vectors.ts from the packages/core ImtTree " +
      "oracle — DO NOT EDIT. Frontier::attach_subtree differential vectors at every close-loop " +
      "rem shape (0 block-aligned, 1, 0b10101011=171, 255, plus a two-attach sequence); " +
      "postState carries the program's stale sub-LOG_B frontier (see the generator's splice " +
      "note). Gate 7 input — SOLR §4.1.",
    treeHeight: H,
    batchB: B,
    logB: LOG_B,
    cases,
  };
  writeJson(CONFORMANCE, "attach_vectors.json", out);
  console.log(`wrote attach_vectors.json (${cases.length} cases, anchors verified)`);
}

main();
