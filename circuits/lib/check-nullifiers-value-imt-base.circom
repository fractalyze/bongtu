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
//   (5) SPEC §6b v2 authority (auditor) envelope: new inputs ecdhPrivateKey,
//       encryptionNonce, authorityPublicKey[2]; new outputs ecdhPublicKey[2] and
//       cipherTextAuthority[l+1] = SymmetricEncrypt over the SAME plaintext the
//       transfer non-repudiation base uses —
//         [inputOwnerPub.x, inputOwnerPub.y] ++ [(inValue,inSalt) x nInputs]
//         ++ [(outOwnerPub.x,.y) x nOutputs] ++ [(outValue,outSalt) x nOutputs]
//       length 2 + 2*nInputs + 4*nOutputs (10 at (nIn=2,nOut=1) => 13 ct elts).
//       So a withdraw's inputs + change note are auditor-decryptable from
//       on-chain data alone; the contract injects the stored arbiter key into
//       authorityPublicKey so a proof not encrypted to it FAILS.
//   (6) PQ hybrid envelope (.dev/pq-envelope-design.md §2): private input
//       kemSs[2] (ML-KEM-768 shared-secret limbs), envelope key = tagged
//       Poseidon(5) fold of ECDH x kemSs, new LAST output kemBinding.
//
// commitment = hash(value, salt, owner public key)
// nullifier  = hash(value, salt, ownerPrivatekey)
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-nullifiers.circom";
include "lib/ecdh.circom";
include "lib/encrypt.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "node_modules/circomlib/circuits/babyjub.circom"; // BabyPbk (owner + ecdh public keys)
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)
include "node_modules/circomlib/circuits/bitify.circom"; // Num2Bits (kemSs limb canonicalization)
include "node_modules/circomlib/circuits/poseidon.circom"; // hybrid-key / kemBinding derivation (pq-envelope-design.md §2)

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
  // §6b v2 authority envelope: ecdhPrivateKey is private; encryptionNonce +
  // authorityPublicKey are public (the contract injects the stored arbiter key).
  signal input ecdhPrivateKey;
  // ML-KEM-768 shared-secret limbs (LE-uint128 halves of ss; PRIVATE).
  signal input kemSs[2];
  signal input encryptionNonce;
  signal input authorityPublicKey[2];

  signal output out;
  signal output ecdhPublicKey[2];

  // authority (non-repudiation) plaintext length + Poseidon-sponge padding.
  var authorityPlainLength = 2 + 2 * nInputs + 4 * nOutputs;
  var lAuth = authorityPlainLength;
  if (lAuth % 3 != 0) {
    lAuth += (3 - (lAuth % 3));
  }
  signal output cipherTextAuthority[lAuth + 1];
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

    // §5.2 CRITICAL correction: a zero-commitment input must NEVER be enabled.
    // The index-keyed IMT commits zeros[0]=0 at every padded / ahead-of-frontier
    // index, so 0 is a GENUINE membership-provable leaf — unlike Zeto's value-keyed
    // SMT, where commitment==0 can never be a member. Meanwhile CheckHashes' zero-
    // commitment escape leaves value/salt/owner UNBOUND. Without this belt an attacker
    // spends a padded 0-leaf at enabled=1 with a fresh nullifier and ARBITRARY value X
    // (membership holds, the enabled-belt above is vacuous at enabled=1) => `out`
    // pays X from nothing (permissionless withdraw drain). Forbidding a zero-commitment
    // enabled input restores the SMT's implicit invariant explicitly. Ref spec §5.2.
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

  // --- §6b v2 authority (auditor) envelope ---------------------------------
  // Same plaintext + Poseidon-sponge encryption the transfer non-repudiation
  // base uses, keyed by ECDH(ecdhPrivateKey, authorityPublicKey). Lets the
  // auditor recover the input owner + each input (value,salt) + the change note
  // (ownerPub,value,salt) from the on-chain cipherTextAuthority alone.
  (ecdhPublicKey[0], ecdhPublicKey[1]) <== BabyPbk()(in <== ecdhPrivateKey);

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

  var plainText[2 + 2 * nInputs + 4 * nOutputs];
  plainText[0] = inputOwnerPubKeyAx;
  plainText[1] = inputOwnerPubKeyAy;
  var idxAuth = 2;
  for (var i = 0; i < nInputs; i++) {
    plainText[idxAuth] = inputValues[i];
    idxAuth++;
    plainText[idxAuth] = inputSalts[i];
    idxAuth++;
  }
  for (var i = 0; i < nOutputs; i++) {
    plainText[idxAuth] = outputOwnerPublicKeys[i][0];
    idxAuth++;
    plainText[idxAuth] = outputOwnerPublicKeys[i][1];
    idxAuth++;
  }
  for (var i = 0; i < nOutputs; i++) {
    plainText[idxAuth] = outputValues[i];
    idxAuth++;
    plainText[idxAuth] = outputSalts[i];
    idxAuth++;
  }

  cipherTextAuthority <== SymmetricEncrypt(2 + 2 * nInputs + 4 * nOutputs)(plainText <== plainText, key <== hybridKey, nonce <== encryptionNonce);
}
