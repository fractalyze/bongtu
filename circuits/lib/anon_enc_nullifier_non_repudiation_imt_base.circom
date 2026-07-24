// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu Unit 0 vendoring + belt, 2026-07-24)
// -------------------------------------------------------
// project-authored, derived from Zeto's non-repudiation SMT base
// (basetokens/anon_enc_nullifier_non_repudiation_base.circom) with the input
// membership proof switched from a value-keyed Sparse Merkle Tree to an
// append-only Incremental Merkle Tree. This file was a git-UNTRACKED local file
// inside the zeto checkout
// (`zeto/zkp/circuits/basetokens/anon_enc_nullifier_non_repudiation_imt_base.circom`)
// — NOT an upstream hyperledger-labs/zeto file, under no version control anywhere,
// yet the bongtu disburse build depended on it via `circom -l`. It is now vendored
// into the bongtu repo.
//
// MODIFICATIONS vs the untracked original:
//   (1) include *path spellings* adjusted so `check-imt-proof.circom` resolves to
//       the vendored sibling in bongtu/circuits/lib (via `-l lib`) while the
//       upstream TRACKED sub-checks (check-positive/hashes/sum/nullifiers,
//       encrypt-outputs, circomlib) still resolve into the pinned zeto checkout
//       (via `-l $ZETO` / `-l $ZETO/node_modules`);
//   (2) §5.2 zero-commitment BELT added at the CheckIMTProof call site (see below):
//       `enabled[i] * IsZero(inputCommitment[i]) === 0`. This changes the r1cs, so
//       the disburse-256 GPU zkey / verifier are regenerated (byte-identity reuse
//       retired). Ref spec §5.2 and docs/zeto-derivation.md.
//
// Everything else (nullifiers, sum/positive checks, receiver + authority
// Poseidon-sponge encryption, subtree gadget, disclosureHash) is unchanged.
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-sum.circom";
include "lib/check-nullifiers.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "lib/encrypt-outputs.circom";
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)

// Zeto anon_enc_nullifier_non_repudiation, with the input-membership proof switched
// from a value-keyed Sparse Merkle Tree to an append-only Incremental Merkle Tree.
// Everything else (nullifiers, sum/positive checks, receiver encryption, and the
// enforced authority disclosure via SymmetricEncrypt) is unchanged from Zeto.
template Zeto(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  signal input inputOwnerPrivateKey;
  signal input ecdhPrivateKey;
  signal input root;
  // IMT membership witness: siblings + insertion index per input (was SMT merkleProof)
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
  signal cipherTexts[nOutputs][4];
  signal output disclosureHash;

  var outputElementsLength = 2 + 2 * nInputs + 2 * nOutputs + 2 * nOutputs;
  var l = outputElementsLength;
  if (l % 3 != 0) {
    l += (3 - (l % 3));
  }
  signal cipherTextAuthority[l+1];
  signal output subtreeRoot;

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

  // depth-log2(nOutputs) Merkle subtree over the output commitments (Poseidon-v1),
  // so the contract can attach the whole batch as one subtree (one-shot root update).
  var TOTAL = 2 * nOutputs - 1;
  signal subNodes[TOTAL];
  for (var i = 0; i < nOutputs; i++) { subNodes[nOutputs - 1 + i] <== outputCommitments[i]; }
  component subHash[nOutputs - 1];
  for (var i = nOutputs - 2; i >= 0; i--) {
    subHash[i] = Poseidon(2);
    subHash[i].inputs[0] <== subNodes[2*i + 1];
    subHash[i].inputs[1] <== subNodes[2*i + 2];
    subNodes[i] <== subHash[i].out;
  }
  subtreeRoot <== subNodes[0];

  CheckHashes(nInputs)(commitmentHashes <== inputCommitments, commitmentInputs <== inAuxInputs);
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== outAuxInputs);

  CheckNullifiers(nInputs)(nullifiers <== nullifiers, values <== inputValues, salts <== inputSalts, ownerPrivateKey <== inputOwnerPrivateKey);

  CheckSum(nInputs, nOutputs)(inputValues <== inputValues, outputValues <== outputValues);

  // Input commitments belong to the append-only IMT with root `root`.
  CheckIMTProof(nInputs, nLevels)(leaves <== inputCommitments, leafIndices <== leafIndices, pathElements <== pathElements, root <== root, enabled <== enabled);

  // §5.2 CRITICAL zero-commitment belt (REQUIRED on every spending base, incl. disburse).
  // The index-keyed IMT commits zeros[0]=0 at every padded / ahead-of-frontier index and
  // at every disburse pad slot, so 0 is a GENUINE membership-provable leaf — unlike Zeto's
  // value-keyed SMT where commitment==0 can never be a member. CheckHashes' zero-commitment
  // escape leaves value/salt/owner UNBOUND, so without this belt a (malicious/compromised)
  // discloser spends a padded 0-leaf at enabled=1 with a fresh nullifier and ARBITRARY value
  // X (membership holds) => CheckSum mints X from nothing. disburse's single input is always
  // enabled=1 (contract-forced), so it IS exploitable and IS in scope. Forbidding a
  // zero-commitment enabled input restores the SMT's implicit invariant explicitly. Ref spec §5.2.
  for (var i = 0; i < nInputs; i++) {
    var isZeroInputCommitment;
    isZeroInputCommitment = IsZero()(in <== inputCommitments[i]);
    enabled[i] * isZeroInputCommitment === 0;   // enabled=1 => inputCommitment != 0
  }

  // Generate cipher text for output utxos (receiver-decryptable)
  (ecdhPublicKey, cipherTexts) <== EncryptOutputs(nOutputs)(ecdhPrivateKey <== ecdhPrivateKey, encryptionNonce <== encryptionNonce, commitmentInputs <== outAuxInputs);

  // generate shared secret for the authority
  var sharedSecretAuthority[2];
  (sharedSecretAuthority) = Ecdh()(privKey <== ecdhPrivateKey, pubKey <== authorityPublicKey);

  // prepare text to be encrypted for the authority (non-repudiation)
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

  // Aggregate all ciphertext elements into ONE public commitment so the on-chain
  // Groth16 verifier has O(1) public inputs. Real ciphertexts are delivered off-chain;
  // disclosureHash binds them on-chain (non-repudiation preserved).
  var NCT = 4 * nOutputs + (l + 1);
  signal ctFlat[NCT];
  var kk = 0;
  for (var i = 0; i < nOutputs; i++) {
    for (var j = 0; j < 4; j++) { ctFlat[kk] <== cipherTexts[i][j]; kk++; }
  }
  for (var i = 0; i < l + 1; i++) { ctFlat[kk] <== cipherTextAuthority[i]; kk++; }
  signal dh[NCT + 1];
  dh[0] <== 0;
  component dhH[NCT];
  for (var i = 0; i < NCT; i++) {
    dhH[i] = Poseidon(2);
    dhH[i].inputs[0] <== dh[i];
    dhH[i].inputs[1] <== ctFlat[i];
    dh[i + 1] <== dhH[i].out;
  }
  disclosureHash <== dh[NCT];
}
