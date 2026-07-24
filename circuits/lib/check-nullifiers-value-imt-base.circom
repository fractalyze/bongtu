// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from zeto zkp/circuits/lib/check-nullifiers-value-base.circom and
// rebased from the value-keyed SMT onto the append-only IMT for bongtu's
// `withdraw` circuit. Edits vs the upstream file (SPEC §4 withdraw deltas):
//   (1) include check-imt-proof.circom instead of check-smt-proof.circom;
//   (2) merkleProof[nInputs][nSMTLevels]  ->  pathElements[nInputs][nLevels]
//       + leafIndices[nInputs]  (both private IMT membership witness);
//   (3) CheckSMTProof(...)  ->  CheckIMTProof(...);
//   (4) comparator GreaterEqThan(100) -> GreaterEqThan(101): summing two
//       100-bit inputs can reach 2^101, which violates GreaterEqThan(100)'s
//       `< 2^100` precondition and would make honest near-max withdrawals lose
//       their witness. 101 bits covers the sum of two 100-bit values exactly.
//
// commitment = hash(value, salt, owner public key)
// nullifier  = hash(value, salt, ownerPrivatekey)
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-nullifiers.circom";
include "lib/check-imt-proof.circom";

template CheckNullifiersInputsOutputsValueIMT(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  // must be properly hashed and trimmed to be compatible with the BabyJub curve.
  signal input inputOwnerPrivateKey;
  signal input root;
  // IMT membership witness: siblings + insertion index per input (was SMT merkleProof)
  signal input pathElements[nInputs][nLevels];
  signal input leafIndices[nInputs];
  signal input enabled[nInputs];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  signal output out;

  var inputOwnerPubKeyAx, inputOwnerPubKeyAy;
  (inputOwnerPubKeyAx, inputOwnerPubKeyAy) = BabyPbk()(in <== inputOwnerPrivateKey);

  CheckPositive(nOutputs)(outputValues <== outputValues);

  CommitmentInputs() inAuxInputs[nInputs];
  for (var i = 0; i < nInputs; i++) {
    inAuxInputs[i].value <== inputValues[i];
    inAuxInputs[i].salt <== inputSalts[i];
    inAuxInputs[i].ownerPublicKey <== [inputOwnerPubKeyAx, inputOwnerPubKeyAy];
  }

  CommitmentInputs() outAuxInputs[nOutputs];
  for (var i = 0; i < nOutputs; i++) {
    outAuxInputs[i].value <== outputValues[i];
    outAuxInputs[i].salt <== outputSalts[i];
    outAuxInputs[i].ownerPublicKey <== outputOwnerPublicKeys[i];
  }

  CheckHashes(nInputs)(commitmentHashes <== inputCommitments, commitmentInputs <== inAuxInputs);

  CheckNullifiers(nInputs)(nullifiers <== nullifiers, values <== inputValues, salts <== inputSalts, ownerPrivateKey <== inputOwnerPrivateKey);
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== outAuxInputs);

  // Input commitments belong to the append-only IMT with root `root`.
  CheckIMTProof(nInputs, nLevels)(leaves <== inputCommitments, leafIndices <== leafIndices, pathElements <== pathElements, root <== root, enabled <== enabled);

  // §5.2 REQUIRED value-belt (contract-derive alone is insufficient). CheckNullifiers
  // and CheckHashes both ACCEPT a zero nullifier / zero commitment with ANY value, and
  // CheckSum adds inputValues[i] UNCONDITIONALLY, so a fabricated input
  // {nullifier=0, commitment=0, value=X, enabled=0} would pass every other constraint
  // and inflate `out` (mint-from-nothing / pool theft). Binding value to `enabled`
  // (which the contract derives as nullifier!=0) makes that witness unsatisfiable:
  //   nullifier=0 => contract injects enabled=0 => value forced 0 (no mint);
  //   nullifier!=0 => enabled=1 => CheckIMTProof requires real membership.
  for (var i = 0; i < nInputs; i++) {
    enabled[i] * (enabled[i] - 1) === 0;        // enabled is boolean
    (1 - enabled[i]) * inputValues[i] === 0;    // a disabled input MUST carry zero value
  }

  // check that the sum of input values is greater than or equal to the sum of output values
  var sumInputs = 0;
  for (var i = 0; i < nInputs; i++) {
    sumInputs = sumInputs + inputValues[i];
  }
  var sumOutputs = 0;
  for (var i = 0; i < nOutputs; i++) {
    sumOutputs = sumOutputs + outputValues[i];
  }

  // 101 bits: the sum of two 100-bit inputs can reach 2^101 - 2.
  var greaterEqThan;
  greaterEqThan = GreaterEqThan(101)(in <== [sumInputs, sumOutputs]);

  greaterEqThan === 1;

  out <== sumInputs - sumOutputs;
}
