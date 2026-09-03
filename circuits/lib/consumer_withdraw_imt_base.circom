// Copyright © 2024 Kaleido, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu U2 consumer family, 2026-09-03)
// ---------------------------------------------------
// Derived from circuits/lib/check-nullifiers-value-imt-base.circom (the
// enterprise withdraw base, ultimately from Zeto's
// lib/check-nullifiers-value-base.circom) for the consumer (no-auditor)
// `withdrawPriv` circuit — OPMOD §2 (.dev/op-module-design.md). The
// enterprise base is NOT edited in place; this is a sibling.
//
// MODIFICATIONS vs check-nullifiers-value-imt-base.circom:
//   (1) NO authority material (OPMOD §2): cipherTextAuthority[lAuth+1],
//       kemBinding, authorityPublicKey[2], the arbiter-side hybrid KDF and its
//       per-op kemSs[2] are entirely absent.
//   (2) NEW receiver ciphertext + view tag for the CHANGE note
//       (OPMOD §3.2/§3.3/§3.5) via ConsumerEncryptOutputs: enterprise withdraw
//       has none — its change is arbiter-recoverable; the consumer sender must
//       be able to recover change from chain scan alone. ECDH against the
//       per-output note-layer VIEW pubkey (NEW private witness
//       outputViewPublicKeys[nOutputs][2]), per-output ML-KEM-768 limbs
//       (kemSs becomes [nOutputs][2], PRIVATE), per-output nonce
//       (encryptionNonce + i), canonical viewTags via Num2Bits_strict.
//
// Every input-side soundness constraint of the parent survives VERBATIM
// (OPMOD §2.1: enabled boolean, value belt, zero-commitment guard,
// CheckPositive, GreaterEqThan(101) conservation, IMT membership).
//
// commitment = hash(value, salt, owner public key)
// nullifier  = hash(value, salt, ownerPrivatekey)
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-nullifiers.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "consumer-encrypt-outputs.circom";   // vendored consumer receiver encryption + view tags (bongtu/circuits/lib, via -l lib)
include "node_modules/circomlib/circuits/babyjub.circom"; // BabyPbk (owner public key)
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)

template BongtuConsumerWithdrawBase(nInputs, nOutputs, nLevels) {
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
  // note-layer VIEW pubkeys, one per output (OPMOD §3.1) — the receiver-ct
  // encryption target; NEVER the spend key the commitment binds.
  signal input outputViewPublicKeys[nOutputs][2];
  signal input ecdhPrivateKey;
  // ML-KEM-768 shared-secret limbs, one fresh encapsulation per OUTPUT
  // (LE-uint128 halves of ss_i; PRIVATE — OPMOD §3.3).
  signal input kemSs[nOutputs][2];
  signal input encryptionNonce;

  signal output out;
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

  CheckNullifiers(nInputs)(nullifiers <== nullifiers, values <== inputValues, salts <== inputSalts, ownerPrivateKey <== inputOwnerPrivateKey);
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== outAuxInputs);

  // Input commitments belong to the append-only IMT with root `root`.
  CheckIMTProof(nInputs, nLevels)(leaves <== inputCommitments, leafIndices <== leafIndices, pathElements <== pathElements, root <== root, enabled <== enabled);

  // §5.2 REQUIRED value-belt (contract-derive alone is insufficient; OPMOD §2.1
  // carries it over verbatim). CheckNullifiers and CheckHashes both ACCEPT a
  // zero nullifier / zero commitment with ANY value, and the sum below adds
  // inputValues[i] UNCONDITIONALLY, so a fabricated input
  // {nullifier=0, commitment=0, value=X, enabled=0} would pass every other
  // constraint and inflate `out` (mint-from-nothing / pool theft). Binding
  // value to `enabled` (which the module derives as nullifier!=0) makes that
  // witness unsatisfiable:
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
    // (membership holds, the enabled-belt above is vacuous at enabled=1) => `out`
    // pays X from nothing (permissionless withdraw drain). Forbidding a zero-commitment
    // enabled input restores the SMT's implicit invariant explicitly. Ref spec §5.2 / OPMOD §2.1.
    var isZeroInputCommitment;
    isZeroInputCommitment = IsZero()(in <== inputCommitments[i]);
    enabled[i] * isZeroInputCommitment === 0;   // enabled=1 => inputCommitment != 0
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

  // Consumer receiver encryption + view tag over the CHANGE note (OPMOD §3):
  // the sender recovers change from chain scan alone — no arbiter recovery
  // path exists in the consumer family.
  (ecdhPublicKey, cipherTexts, viewTags) <== ConsumerEncryptOutputs(nOutputs)(
    ecdhPrivateKey <== ecdhPrivateKey,
    encryptionNonce <== encryptionNonce,
    outputViewPublicKeys <== outputViewPublicKeys,
    outputValues <== outputValues,
    outputSalts <== outputSalts,
    kemSs <== kemSs
  );
}
