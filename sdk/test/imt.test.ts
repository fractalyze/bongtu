// U1 gate — reference single-frontier IMT + Poseidon-v1 parity.
// Run: `npm test` (node --test via tsx). Every assertion below is part of the M0 Done#1 gate.

import { test } from "node:test";
import assert from "node:assert/strict";

import { poseidon2, poseidonN } from "../src/poseidon.js";
import { ImtTree } from "../src/imt.js";

const H = 32;
const B = 16;

// Poseidon-v1 reference (circomlib): the load-bearing parity constant.
const POSEIDON_1_2 =
  7853200120776062878684798364095072458815029376092732009249414926327459813530n;

// A commitment-shaped field element (poseidon4 over value/salt/pubX/pubY), so the
// test leaves resemble the real commitment = poseidon4([value, salt, ownerPubX, ownerPubY]).
function commit(i: number): bigint {
  return poseidonN([BigInt(i + 1), BigInt(i + 1000), BigInt(2 * i + 7), BigInt(3 * i + 11)]);
}

// Fold a leaf up to the root using a returned merkle path.
function foldPath(leaf: bigint, siblings: bigint[], pathIndices: number[]): bigint {
  let cur = BigInt(leaf);
  for (let j = 0; j < siblings.length; j++) {
    cur = pathIndices[j] === 0 ? poseidon2(cur, siblings[j]) : poseidon2(siblings[j], cur);
  }
  return cur;
}

// --- (a) Poseidon-v1 parity gate -------------------------------------------

test("(a) poseidon2(1,2) matches the Poseidon-v1 reference hash", () => {
  assert.equal(poseidon2(1n, 2n), POSEIDON_1_2);
  assert.equal(poseidon2(1, 2), POSEIDON_1_2); // Number inputs coerce identically
  assert.equal(poseidonN([1n, 2n]), POSEIDON_1_2); // variable-arity agrees at arity 2
  assert.equal(typeof poseidon2(1n, 2n), "bigint");
});

test("(a') poseidonN routes fixed arities (3,4) without error", () => {
  assert.equal(typeof poseidonN([1n, 2n, 3n]), "bigint");
  assert.equal(typeof poseidonN([1n, 2n, 3n, 4n]), "bigint");
  assert.throws(() => poseidonN([]), /unsupported arity/);
});

// --- (b) single appends vs the naive dense oracle --------------------------

test("(b) after k single appendLeaf calls, getRoot() === naiveRoot(leafArray, H)", () => {
  for (const k of [0, 1, 2, 17]) {
    const tree = new ImtTree(H, B);
    const leafArray: bigint[] = [];
    for (let i = 0; i < k; i++) {
      const c = commit(i);
      tree.appendLeaf(c);
      leafArray.push(c);
    }
    assert.equal(tree.getNextLeafIndex(), k, `nextLeafIndex after ${k} appends`);
    assert.equal(
      tree.getRoot(),
      ImtTree.naiveRoot(leafArray, H),
      `frontier root != naive dense root after ${k} appends`,
    );
  }
});

// --- computeSubtreeRoot sanity (mirrors the in-circuit subtree gadget) ------

test("computeSubtreeRoot: empty batch = zeros[LOG_B]; matches naive block node", () => {
  const tree = new ImtTree(H, B);
  assert.equal(tree.computeSubtreeRoot([]), tree.zeros[tree.LOG_B]);

  const batch = Array.from({ length: B }, (_, i) => commit(100 + i));
  // The depth-LOG_B tree over the B leaves is exactly the height-LOG_B naiveRoot.
  assert.equal(tree.computeSubtreeRoot(batch), ImtTree.naiveRoot(batch, tree.LOG_B));

  // Fewer than B leaves pads with zeros[0].
  const partial = batch.slice(0, 5);
  assert.equal(tree.computeSubtreeRoot(partial), ImtTree.naiveRoot(partial, tree.LOG_B));
});

// --- (c) attach one aligned B-block vs the naive dense oracle ---------------

test("(c) attachSubtree(16) at an aligned block: getRoot() === naiveRoot(dense, H)", () => {
  const tree = new ImtTree(H, B);
  const batch = Array.from({ length: B }, (_, i) => commit(200 + i));
  const subtreeRoot = tree.computeSubtreeRoot(batch);

  tree.attachSubtree(subtreeRoot, batch);

  assert.equal(tree.getNextLeafIndex(), B);
  // Dense array: the 16 batch leaves fill the first (aligned) block, zeros elsewhere.
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(batch, H));
});

test("(c') attachSubtree rejects a subtreeRoot that disagrees with its leaves", () => {
  const tree = new ImtTree(H, B);
  const batch = Array.from({ length: B }, (_, i) => commit(300 + i));
  assert.throws(() => tree.attachSubtree(999n, batch), /does not match computeSubtreeRoot/);
});

// --- (d) the U3 interleaved differential sequence, checked at EVERY step ----

test("(d) appendLeaf x2 -> attachSubtree(16) -> appendLeaf x1 == naive dense root at every step", () => {
  const tree = new ImtTree(H, B);
  const dense: bigint[] = [];

  // deposit/transfer outputs: two single appends.
  const c0 = commit(1);
  tree.appendLeaf(c0);
  dense[0] = c0;
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "after append #1");

  const c1 = commit(2);
  tree.appendLeaf(c1);
  dense[1] = c1;
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "after append #2");

  // disburse: pad indices 2..15 to the B-boundary as dead zeros, attach at block 1.
  const batch = Array.from({ length: B }, (_, i) => commit(400 + i));
  const subtreeRoot = tree.computeSubtreeRoot(batch);
  tree.attachSubtree(subtreeRoot, batch);
  for (let i = 2; i < B; i++) dense[i] = 0n; // padded dead leaves
  for (let i = 0; i < B; i++) dense[B + i] = batch[i]; // aligned batch block
  assert.equal(tree.getNextLeafIndex(), 2 * B, "nextLeafIndex after attach");
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "after disburse attach");

  // withdraw: one more single append lands at the next real index (2*B).
  const cLast = commit(9);
  tree.appendLeaf(cLast);
  dense[2 * B] = cLast;
  assert.equal(tree.getNextLeafIndex(), 2 * B + 1, "nextLeafIndex after final append");
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "after final append");
});

test("(d') full U3 shape deposit(2)->transfer(2)->disburse(16)->withdraw(1) matches naive at every insert", () => {
  const tree = new ImtTree(H, B);
  const dense: bigint[] = [];
  let idx = 0;

  // deposit(2) + transfer(2) = four single appends
  for (let i = 0; i < 4; i++) {
    const c = commit(500 + i);
    tree.appendLeaf(c);
    dense[idx++] = c;
    assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), `single insert ${i}`);
  }

  // disburse(16): pad 4..15 dead, batch at block 1
  const batch = Array.from({ length: B }, (_, i) => commit(600 + i));
  tree.attachSubtree(tree.computeSubtreeRoot(batch), batch);
  while (idx < B) dense[idx++] = 0n;
  for (let i = 0; i < B; i++) dense[idx++] = batch[i];
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "after disburse");

  // withdraw(1)
  const cw = commit(700);
  tree.appendLeaf(cw);
  dense[idx++] = cw;
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "after withdraw");
});

// --- (e) merkle paths verify against the current root ----------------------

test("(e) merklePath(i) verifies against getRoot() for real leaves after mixed inserts", () => {
  const tree = new ImtTree(H, B);
  const value = new Map<number, bigint>(); // leafIndex -> committed value

  // two single appends
  for (let i = 0; i < 2; i++) {
    const c = commit(800 + i);
    value.set(tree.getNextLeafIndex(), c);
    tree.appendLeaf(c);
  }
  // a batch (with leaves, so paths INTO the batch are reconstructable)
  const blockStart = B; // after pad from index 2
  const batch = Array.from({ length: B }, (_, i) => commit(900 + i));
  tree.attachSubtree(tree.computeSubtreeRoot(batch), batch);
  for (let i = 0; i < B; i++) value.set(blockStart + i, batch[i]);
  // two more single appends after the batch
  for (let i = 0; i < 2; i++) {
    const c = commit(1000 + i);
    value.set(tree.getNextLeafIndex(), c);
    tree.appendLeaf(c);
  }

  // Check paths for: first leaf, a padded-block real leaf, a batch leaf, last leaf.
  const toCheck = [0, 1, blockStart, blockStart + 7, blockStart + B - 1, 2 * B, 2 * B + 1];
  for (const leafIndex of toCheck) {
    const { siblings, pathIndices } = tree.merklePath(leafIndex);
    assert.equal(siblings.length, H);
    assert.equal(pathIndices.length, H);
    const recomputed = foldPath(value.get(leafIndex)!, siblings, pathIndices);
    assert.equal(recomputed, tree.getRoot(), `merkle path for leaf ${leafIndex} != root`);
  }
});

test("(e') merklePath into a batch attached WITHOUT its leaves fails loudly", () => {
  const tree = new ImtTree(H, B);
  tree.appendLeaf(commit(1));
  const batch = Array.from({ length: B }, (_, i) => commit(1100 + i));
  tree.attachSubtree(tree.computeSubtreeRoot(batch)); // no leaves recorded
  assert.throws(() => tree.merklePath(0), /not recorded/);
  assert.throws(() => tree.merklePath(999), /out of range/);
});

// --- randomized differential stress: frontier vs naive across interleavings --

test("stress: frontier root == naive dense root across random append/attach interleavings", () => {
  // Small height so the naive recompute is cheap; exercises odd/even partial-block
  // padding, back-to-back attaches, and appends after attaches.
  const sh = 7;
  const sb = 4;
  let counter = 0;

  for (let seed = 0; seed < 12; seed++) {
    let rng = seed * 2654435761 + 12345;
    const rand = () => {
      rng = (rng * 1103515245 + 12345) & 0x7fffffff;
      return rng;
    };

    const tree = new ImtTree(sh, sb);
    const dense: bigint[] = [];
    const cap = 2 ** sh;

    for (let op = 0; op < 30; op++) {
      const doAttach = rand() % 2 === 0;
      if (doAttach) {
        // pad dense to boundary, then room for a full block?
        let padded = dense.length;
        while (padded % sb !== 0) padded++;
        if (padded + sb > cap) continue;
        while (dense.length % sb !== 0) dense.push(0n);
        const batch = Array.from({ length: sb }, () => commit(counter++));
        tree.attachSubtree(tree.computeSubtreeRoot(batch), batch);
        for (const b of batch) dense.push(b);
      } else {
        if (dense.length + 1 > cap) continue;
        const c = commit(counter++);
        tree.appendLeaf(c);
        dense.push(c);
      }
      assert.equal(tree.getNextLeafIndex(), dense.length, `seed ${seed} op ${op}: index drift`);
      assert.equal(
        tree.getRoot(),
        ImtTree.naiveRoot(dense, sh),
        `seed ${seed} op ${op}: frontier root != naive dense root`,
      );
    }

    // And a sample of real leaves' merkle paths must verify at the final root
    // (first, last, and a few strided interior leaves — enough to catch a
    // frontier/path mismatch without an O(N^2) sweep every run).
    const n = tree.getNextLeafIndex();
    const sample = new Set<number>([0, n - 1]);
    for (let i = 0; i < n; i += Math.max(1, Math.floor(n / 6))) sample.add(i);
    for (const i of sample) {
      const { siblings, pathIndices } = tree.merklePath(i);
      assert.equal(foldPath(dense[i], siblings, pathIndices), tree.getRoot(), `seed ${seed}: path ${i}`);
    }
  }
});

// --- (f) prod geometry H=32 / B=256 (LOG_B=8) — de-risks M1 reuse -----------

test("(f) B=256 attach at H=32 (LOG_B=8): root == naive dense root + a batch-leaf path verifies", () => {
  const bigB = 256;
  const tree = new ImtTree(H, bigB);
  assert.equal(tree.LOG_B, 8);

  // one single append first, so the batch pads 1..255 dead and attaches at block 1.
  const c0 = commit(2000);
  tree.appendLeaf(c0);
  const batch = Array.from({ length: bigB }, (_, i) => commit(3000 + i));
  tree.attachSubtree(tree.computeSubtreeRoot(batch), batch);

  const dense: bigint[] = [c0];
  for (let i = 1; i < bigB; i++) dense[i] = 0n; // padded dead leaves
  for (let i = 0; i < bigB; i++) dense[bigB + i] = batch[i]; // aligned batch block
  assert.equal(tree.getNextLeafIndex(), 2 * bigB);
  assert.equal(tree.getRoot(), ImtTree.naiveRoot(dense, H), "B=256 frontier root != naive");

  // a merkle path into the batch verifies.
  const leafIndex = bigB + 123;
  const { siblings, pathIndices } = tree.merklePath(leafIndex);
  assert.equal(foldPath(batch[123], siblings, pathIndices), tree.getRoot());
});

// --- (g) merklePath into a PADDED DEAD slot returns a verifying path to 0 ----

test("(g) merklePath into a padded dead slot verifies as a zero leaf", () => {
  const tree = new ImtTree(H, B);
  tree.appendLeaf(commit(4000)); // index 0 real
  tree.appendLeaf(commit(4001)); // index 1 real
  // attach a batch -> indices 2..15 become padded dead zeros.
  const batch = Array.from({ length: B }, (_, i) => commit(4100 + i));
  tree.attachSubtree(tree.computeSubtreeRoot(batch), batch);

  for (const deadIndex of [2, 8, 15]) {
    const { siblings, pathIndices } = tree.merklePath(deadIndex);
    assert.equal(foldPath(0n, siblings, pathIndices), tree.getRoot(), `dead slot ${deadIndex} path != root`);
  }
});

// --- (h) error-path atomicity: a rejected attach leaves the tree untouched ---

test("(h) attachSubtree with a bad root on a pending partial block does NOT mutate state", () => {
  const tree = new ImtTree(H, B);
  // leave a pending partial block (nextLeafIndex not B-aligned) so a pre-pad would show.
  tree.appendLeaf(commit(5000));
  tree.appendLeaf(commit(5001));
  tree.appendLeaf(commit(5002));
  const idxBefore = tree.getNextLeafIndex();
  const rootBefore = tree.getRoot();
  assert.equal(idxBefore % B !== 0, true, "precondition: pending partial block");

  const batch = Array.from({ length: B }, (_, i) => commit(5100 + i));
  assert.throws(() => tree.attachSubtree(12345n, batch), /does not match computeSubtreeRoot/);
  assert.equal(tree.getNextLeafIndex(), idxBefore, "index advanced on a rejected attach");
  assert.equal(tree.getRoot(), rootBefore, "root changed on a rejected attach");

  // and the tree is still usable: a valid attach afterward behaves normally.
  tree.attachSubtree(tree.computeSubtreeRoot(batch), batch);
  assert.equal(tree.getNextLeafIndex(), 2 * B);
});
