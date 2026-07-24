// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu Unit 0 vendoring, 2026-07-24)
// -------------------------------------------------
// project-authored, derived from Zeto's SMT membership gadgets (CheckSMTProof /
// SMTVerifier). This file was a git-UNTRACKED local file inside the zeto checkout
// (`zeto/zkp/circuits/lib/check-imt-proof.circom`) — it is NOT an upstream
// hyperledger-labs/zeto file and was under no version control anywhere, yet the
// bongtu build depended on it via `circom -l`. It is now vendored into the bongtu
// repo verbatim (only the provenance header and the include *path spellings* below
// differ from the untracked original — both resolve to the identical circomlib
// targets, so the compiled r1cs is unchanged). The IMT membership defined here is
// belt-gated at its call sites (transfer / withdraw / disburse bases) by
// `enabled[i] * IsZero(inputCommitment[i]) === 0`; see spec §5.2 and
// docs/zeto-derivation.md.
pragma circom 2.2.2;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/switcher.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/comparators.circom";

// CheckIMTProof: inclusion proof in an append-only Incremental Merkle Tree
// (Tornado / Privacy-Cash style), replacing Zeto's value-keyed CheckSMTProof.
//
// SMT vs IMT: in the SMT the leaf position is the *key* (commitment value), so a
// batch of N commitments lands at N scattered positions. In the IMT the position is
// the *insertion index*, so a contiguous batch forms a complete subtree — which is
// what lets the contract update the root in one O(depth) shot (subtree-attach)
// instead of N * O(depth) per-leaf inserts. We don't lose anything: absence /
// double-spend is enforced by the nullifier set, not by tree non-membership.
//
// For each input i: fold `leaves[i]` up the tree using pathElements[i] as siblings,
// with the left/right order at each level taken from the bits of leafIndices[i].
// The computed root must equal `root` when enabled[i] == 1.
template CheckIMTProof(nInputs, nLevels) {
  signal input leaves[nInputs];
  signal input leafIndices[nInputs];          // insertion index of each leaf
  signal input pathElements[nInputs][nLevels]; // sibling per level
  signal input root;
  signal input enabled[nInputs];

  component idxBits[nInputs];
  component sw[nInputs][nLevels];
  component h[nInputs][nLevels];
  signal cur[nInputs][nLevels + 1];

  for (var i = 0; i < nInputs; i++) {
    // decompose the index into path bits (bit j == 0 => current node is the left child)
    idxBits[i] = Num2Bits(nLevels);
    idxBits[i].in <== leafIndices[i];

    cur[i][0] <== leaves[i];
    for (var j = 0; j < nLevels; j++) {
      // Switcher swaps (L,R) when sel==1: sel=0 -> (cur,sibling), sel=1 -> (sibling,cur)
      sw[i][j] = Switcher();
      sw[i][j].sel <== idxBits[i].out[j];
      sw[i][j].L <== cur[i][j];
      sw[i][j].R <== pathElements[i][j];

      h[i][j] = Poseidon(2);
      h[i][j].inputs[0] <== sw[i][j].outL;
      h[i][j].inputs[1] <== sw[i][j].outR;
      cur[i][j + 1] <== h[i][j].out;
    }

    // only bind to the on-chain root for real (enabled) inputs; padding inputs skip
    ForceEqualIfEnabled()(enabled <== enabled[i], in <== [cur[i][nLevels], root]);
  }
}
