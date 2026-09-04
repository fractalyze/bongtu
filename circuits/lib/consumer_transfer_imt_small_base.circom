// Copyright © 2024 Kaleido, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu U2 consumer family, 2026-09-03)
// ---------------------------------------------------
// Derived from circuits/lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom
// (the enterprise small transfer base, ultimately from Zeto's
// basetokens/anon_enc_nullifier_non_repudiation_base.circom) for the consumer
// (no-auditor) `transferPriv` / `transfer10x2Priv` circuits — OPMOD §2
// (.dev/op-module-design.md). The enterprise base is NOT edited in place;
// this is a sibling.
//
// MODIFICATIONS vs anon_enc_nullifier_non_repudiation_imt_small_base.circom:
//   (1) NO authority material (OPMOD §2): cipherTextAuthority[l+1], kemBinding,
//       authorityPublicKey[2], the arbiter-side hybrid KDF and its per-op
//       kemSs[2] are entirely absent.
//   (2) receiver encryption is the consumer hybrid (OPMOD §3.2/§3.3/§3.5):
//       ConsumerEncryptOutputs replaces EncryptOutputsPerOutputNonce — ECDH
//       against per-output note-layer VIEW pubkeys (NEW private witness
//       outputViewPublicKeys[nOutputs][2]; commitments keep binding the SPEND
//       key), per-output ML-KEM-768 limbs (kemSs becomes [nOutputs][2],
//       PRIVATE), tagged Poseidon(5) receiver keys, the per-output nonce rule
//       (encryptionNonce + i) KEPT, plus NEW canonical viewTags[nOutputs]
//       outputs (Num2Bits_strict) declared as the LAST output run.
//
// Every input-side soundness constraint of the parent survives VERBATIM
// (OPMOD §2.1: enabled boolean, value belt, zero-commitment guard,
// CheckPositive, CheckSum, IMT membership) — none is implied by the additions,
// and deleting any one reopens a documented mint-from-nothing.
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-sum.circom";
include "lib/check-nullifiers.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "consumer-encrypt-outputs.circom";   // vendored consumer receiver encryption + view tags (bongtu/circuits/lib, via -l lib)
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)

template BongtuConsumerTransfer(nInputs, nOutputs, nLevels) {
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
  signal input pathElements[nInputs][nLevels];
  signal input leafIndices[nInputs];
  signal input enabled[nInputs];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  // note-layer VIEW pubkeys, one per output (OPMOD §3.1) — the receiver-ct
  // encryption target; NEVER the spend key the commitment binds.
  signal input outputViewPublicKeys[nOutputs][2];
  signal input encryptionNonce;

  signal output ecdhPublicKey[2];
  signal output cipherTexts[nOutputs][4];
  // NEW (OPMOD §3.2): canonical 8-bit discovery tags, the LAST output run.
  signal output viewTags[nOutputs];

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

  // §5.2 REQUIRED value-belt (contract-derive alone is insufficient; OPMOD §2.1
  // carries it over verbatim). CheckNullifiers and CheckHashes both ACCEPT a
  // zero nullifier / zero commitment with ANY value, and CheckSum adds
  // inputValues[i] UNCONDITIONALLY, so a fabricated input
  // {nullifier=0, commitment=0, value=X, enabled=0} would pass every other
  // constraint and inflate the balance (mint-from-nothing). Binding value to
  // `enabled` (which the module derives as nullifier!=0) makes that witness
  // unsatisfiable:
  //   nullifier=0 => module injects enabled=0 => value forced 0 (no mint);
  //   nullifier!=0 => enabled=1 => CheckIMTProof requires real membership.
  for (var i = 0; i < nInputs; i++) {
    enabled[i] * (enabled[i] - 1) === 0;        // enabled is boolean
    (1 - enabled[i]) * inputValues[i] === 0;    // a disabled input MUST carry zero value

    // §5.2 CRITICAL correction: a zero-commitment input must NEVER be enabled.
    // The index-keyed IMT commits zeros[0]=0 at every padded / ahead-of-frontier
    // index, so 0 is a GENUINE membership-provable leaf — unlike Zeto's value-keyed
    // SMT, where commitment==0 can never be a member. Meanwhile CheckHashes' zero-
    // commitment escape leaves value/salt/owner UNBOUND. Without this belt an attacker
    // spends a padded 0-leaf at enabled=1 with a fresh nullifier and ARBITRARY value X
    // (membership holds, the enabled-belt above is vacuous at enabled=1) => CheckSum
    // mints X from nothing. Forbidding a zero-commitment enabled input restores the
    // SMT's implicit invariant explicitly. Ref spec §5.2 / OPMOD §2.1.
    var isZeroInputCommitment;
    isZeroInputCommitment = IsZero()(in <== inputCommitments[i]);
    enabled[i] * isZeroInputCommitment === 0;   // enabled=1 => inputCommitment != 0
  }

  // Consumer receiver encryption + view tags (OPMOD §3). Fixed output order
  // (the wallet builder pins it): output 0 = the PAYMENT note (recipient),
  // output 1 = the CHANGE note (sender). Each receiver ciphertext i uses
  // nonce encryptionNonce + i (OPMOD §3.5), so a self-send does not reuse a
  // sponge keystream; the receiver decrypts ct_i with nonce + i.
  (ecdhPublicKey, cipherTexts, viewTags) <== ConsumerEncryptOutputs(nOutputs)(
    ecdhPrivateKey <== ecdhPrivateKey,
    encryptionNonce <== encryptionNonce,
    outputViewPublicKeys <== outputViewPublicKeys,
    outputValues <== outputValues,
    outputSalts <== outputSalts,
    kemSs <== kemSs
  );
}
