// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu withdraw (2-in / 1-out): withdraw_nullifier rebased onto the append-only
// IMT (depth 32), with the comparator widened to GreaterEqThan(101) so honest
// near-max withdrawals (sum of two 100-bit inputs, up to ~2^101) keep a witness.
//
// Public: [nullifiers, outputCommitments, root, enabled] + circuit output `out`.
include "check-nullifiers-value-imt-base.circom";

component main {
  public [ nullifiers, outputCommitments, root, enabled ]
} = CheckNullifiersInputsOutputsValueIMT(2, 1, 32);
