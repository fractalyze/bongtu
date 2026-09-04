// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu withdrawPriv (2-in / 1-out + proof-bound public recipient): the
// CONSUMER (no-auditor) withdraw — OPMOD §2 (.dev/op-module-design.md).
// Same input-side soundness belts as the enterprise withdraw, NO authority
// material, and a NEW hybrid receiver ciphertext + view tag over the CHANGE
// note (enterprise withdraw has none — its change is arbiter-recoverable; the
// consumer sender must recover change from chain scan alone).
//
// Public (16): [0]=out [1..2]=ecdhPublicKey [3..6]=cipherTexts[1][4]
//              [7]=viewTags[1] [8..9]=nullifiers[2] [10]=root
//              [11..12]=enabled[2] (module-injected)
//              [13]=outputCommitments[0] (the change note)
//              [14]=encryptionNonce [15]=recipient
// Absent vs enterprise withdraw (uint[27]): cipherTextAuthority[13],
// kemBinding, authorityPublicKey[2]. Added: cipherTexts[1][4], viewTags[1].
include "consumer_withdraw_imt_base.circom";

// Wrapper over the consumer spending base: relays its IO unchanged and appends
// ONE public input, `recipient` — the L1 address the module pays instead of
// msg.sender, so a stealth withdraw can be relayer-submitted without the
// relayer being able to redirect the funds (the module range-checks uint160
// and pays it, mirroring the enterprise withdraw). The square constraint is
// the standard calldata-binding idiom (a bare unused input would be pruned by
// the compiler and drop out of the proof).
template BongtuWithdrawPriv(nInputs, nOutputs, nLevels) {
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
  signal input outputViewPublicKeys[nOutputs][2];
  signal input ecdhPrivateKey;
  signal input kemSs[nOutputs][2];
  signal input encryptionNonce;
  signal input recipient;

  signal output out;
  signal output ecdhPublicKey[2];
  signal output cipherTexts[nOutputs][4];
  signal output viewTags[nOutputs];

  component base = BongtuConsumerWithdrawBase(nInputs, nOutputs, nLevels);
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
  base.outputViewPublicKeys <== outputViewPublicKeys;
  base.ecdhPrivateKey <== ecdhPrivateKey;
  base.kemSs <== kemSs;
  base.encryptionNonce <== encryptionNonce;

  out <== base.out;
  ecdhPublicKey <== base.ecdhPublicKey;
  cipherTexts <== base.cipherTexts;
  viewTags <== base.viewTags;

  // Bind recipient into the proof (see the template comment).
  signal recipientSquare;
  recipientSquare <== recipient * recipient;
}

component main {
  public [ nullifiers, root, enabled, outputCommitments, encryptionNonce, recipient ]
} = BongtuWithdrawPriv(2, 1, 32);
