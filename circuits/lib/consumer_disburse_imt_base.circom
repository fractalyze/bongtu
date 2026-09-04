// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu U2 consumer family, 2026-09-03)
// ---------------------------------------------------
// project-authored, derived from
// circuits/lib/anon_enc_nullifier_non_repudiation_imt_base.circom (the
// enterprise disburse base, itself derived from Zeto's non-repudiation SMT
// base) for the consumer (no-auditor) `disbursePriv` / `disbursePriv256`
// circuits — OPMOD §2/§4 (.dev/op-module-design.md). The enterprise base is
// NOT edited in place; this is a sibling.
//
// MODIFICATIONS vs anon_enc_nullifier_non_repudiation_imt_base.circom:
//   (1) NO authority material (OPMOD §2): cipherTextAuthority[l+1], kemBinding,
//       authorityPublicKey[2], the arbiter-side hybrid KDF and its per-op
//       kemSs[2] are entirely absent.
//   (2) receiver encryption is the consumer hybrid (OPMOD §3.2/§3.3/§3.5):
//       ConsumerEncryptOutputs replaces EncryptOutputs — ECDH against
//       per-output note-layer VIEW pubkeys (NEW private witness
//       outputViewPublicKeys[nOutputs][2]), per-output ML-KEM-768 limbs
//       (kemSs becomes [nOutputs][2], PRIVATE), per-output nonce
//       (encryptionNonce + i — NEW here: the enterprise disburse shares one
//       nonce and needs the assembly-time assertDistinctOwnerPubkeys guard;
//       the nonce offset kills the two-time-pad class structurally, OPMOD
//       §3.5), plus internal canonical viewTags (Num2Bits_strict).
//   (3) EXTENDED disclosureHash fold (OPMOD §4.2): the same Poseidon(2) chain
//       seeded at 0, over receiverCts[4B] ++ viewTags[B] ++
//       outputCommitments[B] (three contiguous runs, each in leaf order —
//       6B elements; 1536 at B=256) instead of the enterprise
//       cts ++ cipherTextAuthority preimage. The SAME outputCommitments
//       witnesses feed (a) the CheckHashes note binding, (b) the subtree
//       builder whose root is the subtreeRoot output, and (c) this fold — so a
//       published array matching disclosureHash is elementwise equal to the
//       circuit's view of the batch, and its commitment run necessarily folds
//       to subtreeRoot. The two families' folds are domain-separated by
//       construction (element counts and content classes differ; each
//       verifier only meets its own family's proofs).
//
// The enabled-boolean + value-belt pair stays ABSENT, exactly as in the
// parent (OPMOD §2.1 "disburse-base exception"): soundness rests on the
// caller reverting ZeroNullifier on a zero nullifier and THEN injecting
// enabled[0] = 1 unconditionally — for the consumer family that compensating
// sequence is a ConsumerDisburseModule contract obligation, reviewed at
// registration. The §5.2 zero-commitment guard IS present (REQUIRED).
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-sum.circom";
include "lib/check-nullifiers.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "consumer-encrypt-outputs.circom";   // vendored consumer receiver encryption + view tags (bongtu/circuits/lib, via -l lib)
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)
include "node_modules/circomlib/circuits/poseidon.circom"; // subtree gadget + disclosureHash fold

template BongtuConsumerDisburse(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  signal input inputOwnerPrivateKey;
  signal input ecdhPrivateKey;
  // ML-KEM-768 shared-secret limbs, one fresh encapsulation per OUTPUT
  // (LE-uint128 halves of ss_i; PRIVATE — OPMOD §3.3).
  signal input kemSs[nOutputs][2];
  signal input root;
  // IMT membership witness: siblings + insertion index per input (was SMT merkleProof)
  signal input pathElements[nInputs][nLevels];
  signal input leafIndices[nInputs];
  signal input enabled[nInputs];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  // note-layer VIEW pubkeys, one per output (OPMOD §3.1) — the receiver-ct
  // encryption target; NEVER the spend key the commitment binds. Pad slots
  // carry a fresh throwaway view identity (OPMOD §4.5).
  signal input outputViewPublicKeys[nOutputs][2];
  signal input encryptionNonce;

  signal output ecdhPublicKey[2];
  // NOT outputs: receiver cts + view tags ride in the `disclosure` calldata
  // array, totally ordered and bound by the extended fold below (OPMOD §4.1).
  signal cipherTexts[nOutputs][4];
  signal viewTags[nOutputs];
  signal output disclosureHash;
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
  // so the module can attach the whole batch as one subtree (one-shot root update).
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

  // §5.2 CRITICAL zero-commitment belt (REQUIRED on every spending base, incl.
  // disburse; OPMOD §2.1 carries it over verbatim). The index-keyed IMT commits
  // zeros[0]=0 at every padded / ahead-of-frontier index, so 0 is a GENUINE,
  // membership-provable leaf — unlike Zeto's value-keyed SMT where commitment==0
  // can never be a member. CheckHashes' zero-commitment escape leaves
  // value/salt/owner UNBOUND, so without this belt a discloser spends a padded
  // 0-leaf at enabled=1 with a fresh nullifier and ARBITRARY value X
  // (membership holds) => CheckSum mints X from nothing. disburse's single
  // input is always enabled=1 (module-forced after a ZeroNullifier revert —
  // the OPMOD §2.1 module obligation), so it IS exploitable and IS in scope.
  for (var i = 0; i < nInputs; i++) {
    var isZeroInputCommitment;
    isZeroInputCommitment = IsZero()(in <== inputCommitments[i]);
    enabled[i] * isZeroInputCommitment === 0;   // enabled=1 => inputCommitment != 0
  }

  // Consumer receiver encryption + view tags (OPMOD §3): hybrid keys, VIEW-key
  // ECDH, per-output nonce (encryptionNonce + i — no duplicate-recipient ban
  // needed at assembly, unlike the enterprise shared-nonce disburse).
  (ecdhPublicKey, cipherTexts, viewTags) <== ConsumerEncryptOutputs(nOutputs)(
    ecdhPrivateKey <== ecdhPrivateKey,
    encryptionNonce <== encryptionNonce,
    outputViewPublicKeys <== outputViewPublicKeys,
    outputValues <== outputValues,
    outputSalts <== outputSalts,
    kemSs <== kemSs
  );

  // EXTENDED fold (OPMOD §4.2): aggregate the whole disclosure — receiver cts
  // (flattened 4i+j, leaf order), then all viewTags, then all output
  // commitments — into ONE public commitment so the on-chain Groth16 verifier
  // has O(1) public inputs. The real elements are delivered as the module's
  // `disclosure` calldata array; disclosureHash binds them on-chain, and any
  // permutation is a different hash (the order is total and consensus).
  var NCT = 6 * nOutputs;
  signal ctFlat[NCT];
  var kk = 0;
  for (var i = 0; i < nOutputs; i++) {
    for (var j = 0; j < 4; j++) { ctFlat[kk] <== cipherTexts[i][j]; kk++; }
  }
  for (var i = 0; i < nOutputs; i++) { ctFlat[kk] <== viewTags[i]; kk++; }
  for (var i = 0; i < nOutputs; i++) { ctFlat[kk] <== outputCommitments[i]; kk++; }
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
