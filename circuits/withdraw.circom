// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu withdraw (2-in / 1-out): withdraw_nullifier rebased onto the append-only
// IMT (depth 32), comparator widened to GreaterEqThan(101), PLUS an in-circuit
// authority (auditor) envelope (SPEC §6b v2) so the spent inputs + change note
// are auditor-decryptable from on-chain data alone.
//
// Public (27): [0]=out [1..2]=ecdhPublicKey [3..15]=cipherTextAuthority[13]
//              [16]=kemBinding [17..18]=nullifiers [19]=root [20..21]=enabled
//              [22]=outputCommitments[0] [23]=encryptionNonce
//              [24..25]=authorityPublicKey [26]=recipient
include "check-nullifiers-value-imt-base.circom";

// Wrapper over the shared spending base: relays its IO unchanged and appends
// ONE public input, `recipient` — the L1 address the pool pays instead of
// msg.sender, so a stealth withdraw can be relayer-submitted without the
// relayer being able to redirect the funds. The square constraint is the
// standard calldata-binding idiom (a bare unused input would be pruned by the
// compiler and drop out of the proof).
template BongtuWithdraw(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  signal input inputOwnerPrivateKey;
  signal input root;
  signal input pathElements[nInputs][nLevels];
  signal input leafIndices[nInputs];
  signal input enabled[nInputs];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  signal input ecdhPrivateKey;
  signal input kemSs[2];
  signal input encryptionNonce;
  signal input authorityPublicKey[2];
  signal input recipient;

  signal output out;
  signal output ecdhPublicKey[2];

  // Same sponge-padded length the base computes for ITS cipherTextAuthority —
  // the two declarations must agree or the relay wiring below won't compile.
  var authorityPlainLength = 2 + 2 * nInputs + 4 * nOutputs;
  var lAuth = authorityPlainLength;
  if (lAuth % 3 != 0) {
    lAuth += (3 - (lAuth % 3));
  }
  signal output cipherTextAuthority[lAuth + 1];
  signal output kemBinding;

  component base = CheckNullifiersInputsOutputsValueIMT(nInputs, nOutputs, nLevels);
  base.nullifiers <== nullifiers;
  base.inputCommitments <== inputCommitments;
  base.inputValues <== inputValues;
  base.inputSalts <== inputSalts;
  base.inputOwnerPrivateKey <== inputOwnerPrivateKey;
  base.root <== root;
  base.pathElements <== pathElements;
  base.leafIndices <== leafIndices;
  base.enabled <== enabled;
  base.outputCommitments <== outputCommitments;
  base.outputValues <== outputValues;
  base.outputSalts <== outputSalts;
  base.outputOwnerPublicKeys <== outputOwnerPublicKeys;
  base.ecdhPrivateKey <== ecdhPrivateKey;
  base.kemSs <== kemSs;
  base.encryptionNonce <== encryptionNonce;
  base.authorityPublicKey <== authorityPublicKey;

  out <== base.out;
  ecdhPublicKey <== base.ecdhPublicKey;
  cipherTextAuthority <== base.cipherTextAuthority;
  kemBinding <== base.kemBinding;

  // Bind recipient into the proof (see the template comment).
  signal recipientSquare;
  recipientSquare <== recipient * recipient;
}

component main {
  public [ nullifiers, root, enabled, outputCommitments, encryptionNonce, authorityPublicKey, recipient ]
} = BongtuWithdraw(2, 1, 32);
