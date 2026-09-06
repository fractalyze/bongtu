// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu ct-free enterprise family, 2026-09-06)
// ---------------------------------------------------------
// project-authored, derived from the sibling
// `anon_enc_nullifier_non_repudiation_imt_base.circom` (itself vendored from an
// untracked Zeto-derived local file — see that file's provenance header) for
// the DEDICATED enterprise pool: the receiver-decryptable ciphertext is
// REMOVED from the constraint system so no classical-ECDH-only receiver
// material ever reaches the chain (harvest-now-decrypt-later closure —
// docs/security-model.md). Recipient discovery on a ct-free pool is served by
// the institution's indexer; the off-chain receipt convention is the
// recipient's institution-independent verification path.
//
// MODIFICATIONS vs the parent base (the ONLY semantic delta):
//   (1) `EncryptOutputs` is gone. `ecdhPublicKey` is derived directly via
//       BabyPbk (the arbiter's classical ECDH half of the hybrid authority
//       envelope still needs it public);
//   (2) every `cipherTexts[i][j]` internal signal is CONSTRAINED TO ZERO. The
//       `disclosureHash` fold keeps its full shape — 4·nOutputs (now zero)
//       receiver elements ++ the authority ciphertext — so the contract's
//       `disburseCiphertextLen` check, the DisburseCiphertexts event, and the
//       indexer's fold-recompute disclosure alarm all work unchanged: the
//       discloser publishes zeros in the receiver run and any deviation alarms
//       exactly as today (layout preservation —
//       .dev/intents/enterprise-ctfree-pool/spec.md).
//
// Everything else — the §5.2 zero-commitment belt, IMT membership, nullifiers,
// sum/positive checks, the subtree gadget, the hybrid (ECDH x ML-KEM-768)
// authority envelope, kemBinding-last ordering, the disclosureHash fold — is
// verbatim from the parent. The parent's DELIBERATE value-belt omission (its
// compensating contract obligation: `ZeroNullifier` revert + unconditional
// `enabled[0] = 1` injection) carries over unchanged.
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-sum.circom";
include "lib/check-nullifiers.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "lib/ecdh.circom";          // authority ECDH (was transitive via the dropped encrypt-outputs include)
include "lib/encrypt.circom";       // SymmetricEncrypt for the authority envelope (same reason)
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)
include "node_modules/circomlib/circuits/bitify.circom"; // Num2Bits (kemSs limb canonicalization)
include "node_modules/circomlib/circuits/poseidon.circom"; // hybrid-key / kemBinding derivation (pq-envelope-design.md §2)

template ZetoCtf(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  signal input inputOwnerPrivateKey;
  signal input ecdhPrivateKey;
  // ML-KEM-768 shared-secret limbs (LE-uint128 halves of ss; PRIVATE).
  signal input kemSs[2];
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
  // LAST output so existing output indices are stable and every public-input
  // index shifts by exactly +1 (pq-envelope-design.md §3).
  signal output kemBinding;

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

  // Ct-free: no receiver-decryptable ciphertext exists. The ephemeral ECDH public
  // key is still published (the arbiter derives the authority envelope's classical
  // half from it), and the receiver-ct run entering the disclosureHash fold is
  // pinned to zero so the fold — and therefore the contract's length check and the
  // indexer's disclosure alarm — keeps the parent's exact shape.
  var ecdhPubAx, ecdhPubAy;
  (ecdhPubAx, ecdhPubAy) = BabyPbk()(in <== ecdhPrivateKey);
  ecdhPublicKey[0] <== ecdhPubAx;
  ecdhPublicKey[1] <== ecdhPubAy;
  for (var i = 0; i < nOutputs; i++) {
    for (var j = 0; j < 4; j++) {
      cipherTexts[i][j] <== 0;
    }
  }

  // generate shared secret for the authority
  var sharedSecretAuthority[2];
  (sharedSecretAuthority) = Ecdh()(privKey <== ecdhPrivateKey, pubKey <== authorityPublicKey);

  // --- PQ hybrid key (pq-envelope-design.md §2) ---
  // Canonical-encoding hygiene: each limb is a genuine 128-bit value.
  component kemSsRange[2];
  for (var i = 0; i < 2; i++) {
    kemSsRange[i] = Num2Bits(128);
    kemSsRange[i].in <== kemSs[i];
  }
  // Frozen domain-separation tags (sha256(ASCII) mod r):
  //   TAG_K0 = sha256("bongtu/pq-envelope/v1/key0"), TAG_K1 = .../key1,
  //   TAG_BIND = .../binding. Key derivation (arity 5) and binding (arity 3)
  //   are separated by both tag and arity.
  var TAG_K0 = 10398998902367040515226727887904115149378422647845688990538198988921570667720;
  var TAG_K1 = 7025394518961265764175593663800963341053996587382265036146196548941915994055;
  var TAG_BIND = 5518019128667894418081277213291049553290157756968653594844689494754896839788;
  signal hybridKey[2];
  hybridKey[0] <== Poseidon(5)([TAG_K0, sharedSecretAuthority[0], sharedSecretAuthority[1], kemSs[0], kemSs[1]]);
  hybridKey[1] <== Poseidon(5)([TAG_K1, sharedSecretAuthority[0], sharedSecretAuthority[1], kemSs[0], kemSs[1]]);
  kemBinding <== Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]]);

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

  cipherTextAuthority <== SymmetricEncrypt(2 + 2 * nInputs + 4 * nOutputs)(plainText <== plainText, key <== hybridKey, nonce <== encryptionNonce);

  // Aggregate all ciphertext elements into ONE public commitment so the on-chain
  // Groth16 verifier has O(1) public inputs. The receiver run is all zeros on this
  // base; disclosureHash still binds the full run so the off-chain delivery and the
  // indexer's fold-recompute alarm keep the parent's exact shape (non-repudiation
  // of the authority envelope preserved).
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
