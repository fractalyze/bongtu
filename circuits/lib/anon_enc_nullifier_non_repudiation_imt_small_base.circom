// Copyright © 2024 Kaleido, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Derived from Zeto (https://github.com/hyperledger-labs/zeto) and MODIFIED for
// bongtu: a reduced-arity (2-in/2-out) non-repudiation base with the ciphertext
// re-exposed as public signals and the input value bound to `enabled`.
pragma circom 2.2.2;

// Derived from zeto basetokens/anon_enc_nullifier_non_repudiation_imt_base.circom
// for the bongtu `transfer` circuit (small arity, 2-in / 2-out).
//
// Differences from the 256 IMT base (SPEC §4):
//   (a) small arity (default 2x2) — the subtree gadget and disclosureHash the
//       256 base needs to keep verifier gas bounded are dropped here;
//   (b) NO subtree gadget;
//   (c) NO disclosureHash;
//   (d) outputCommitments, cipherTexts and cipherTextAuthority are RE-EXPOSED
//       as public signals (outputCommitments via the top-level `public` list;
//       cipherTexts / cipherTextAuthority as circuit outputs) so the contract
//       binds the leaves and ciphertext directly from the very bytes the circuit
//       emits — at this arity the ciphertext rides cheaply as public signals.
//
// Membership is the append-only IMT (check-imt-proof, depth `nLevels`).
// Everything else (nullifiers, sum/positive checks, receiver + authority
// Poseidon-sponge encryption) is unchanged from the zeto non-repudiation base.

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-sum.circom";
include "lib/check-nullifiers.circom";
include "lib/check-imt-proof.circom";
include "lib/encrypt-outputs.circom";
include "node_modules/circomlib/circuits/babyjub.circom";

template ZetoTransferSmall(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  signal input inputOwnerPrivateKey;
  signal input ecdhPrivateKey;
  signal input root;
  signal input pathElements[nInputs][nLevels];
  signal input leafIndices[nInputs];
  signal input enabled[nInputs];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  signal input encryptionNonce;
  signal input authorityPublicKey[2];

  signal output ecdhPublicKey[2];
  signal output cipherTexts[nOutputs][4];

  // authority (non-repudiation) plaintext length + Poseidon-sponge padding
  var outputElementsLength = 2 + 2 * nInputs + 4 * nOutputs;
  var l = outputElementsLength;
  if (l % 3 != 0) {
    l += (3 - (l % 3));
  }
  signal output cipherTextAuthority[l + 1];

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
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== outAuxInputs);

  CheckNullifiers(nInputs)(nullifiers <== nullifiers, values <== inputValues, salts <== inputSalts, ownerPrivateKey <== inputOwnerPrivateKey);

  CheckSum(nInputs, nOutputs)(inputValues <== inputValues, outputValues <== outputValues);

  // Input commitments belong to the append-only IMT with root `root`.
  CheckIMTProof(nInputs, nLevels)(leaves <== inputCommitments, leafIndices <== leafIndices, pathElements <== pathElements, root <== root, enabled <== enabled);

  // §5.2 REQUIRED value-belt (contract-derive alone is insufficient). CheckNullifiers
  // and CheckHashes both ACCEPT a zero nullifier / zero commitment with ANY value, and
  // CheckSum adds inputValues[i] UNCONDITIONALLY, so a fabricated input
  // {nullifier=0, commitment=0, value=X, enabled=0} would pass every other constraint
  // and inflate the balance (mint-from-nothing). Binding value to `enabled` (which the
  // contract derives as nullifier!=0) makes that witness unsatisfiable:
  //   nullifier=0 => contract injects enabled=0 => value forced 0 (no mint);
  //   nullifier!=0 => enabled=1 => CheckIMTProof requires real membership.
  for (var i = 0; i < nInputs; i++) {
    enabled[i] * (enabled[i] - 1) === 0;        // enabled is boolean
    (1 - enabled[i]) * inputValues[i] === 0;    // a disabled input MUST carry zero value
  }

  // Receiver-decryptable ciphertext (public output — contract binds it directly).
  (ecdhPublicKey, cipherTexts) <== EncryptOutputs(nOutputs)(ecdhPrivateKey <== ecdhPrivateKey, encryptionNonce <== encryptionNonce, commitmentInputs <== outAuxInputs);

  // Authority (non-repudiation) envelope.
  var sharedSecretAuthority[2];
  (sharedSecretAuthority) = Ecdh()(privKey <== ecdhPrivateKey, pubKey <== authorityPublicKey);

  var plainText[2 + 2 * nInputs + 4 * nOutputs];
  plainText[0] = inputOwnerPubKeyAx;
  plainText[1] = inputOwnerPubKeyAy;
  var idx1 = 2;
  for (var i = 0; i < nInputs; i++) {
    plainText[idx1] = inputValues[i];
    idx1++;
    plainText[idx1] = inputSalts[i];
    idx1++;
  }
  for (var i = 0; i < nOutputs; i++) {
    plainText[idx1] = outputOwnerPublicKeys[i][0];
    idx1++;
    plainText[idx1] = outputOwnerPublicKeys[i][1];
    idx1++;
  }
  for (var i = 0; i < nOutputs; i++) {
    plainText[idx1] = outputValues[i];
    idx1++;
    plainText[idx1] = outputSalts[i];
    idx1++;
  }

  cipherTextAuthority <== SymmetricEncrypt(2 + 2 * nInputs + 4 * nOutputs)(plainText <== plainText, key <== sharedSecretAuthority, nonce <== encryptionNonce);
}
