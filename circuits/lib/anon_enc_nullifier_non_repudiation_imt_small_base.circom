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
//   (e) PQ hybrid envelope (.dev/pq-envelope-design.md §2): private input
//       kemSs[2] (ML-KEM-768 shared-secret limbs), envelope key = tagged
//       Poseidon(5) fold of ECDH x kemSs, new LAST output kemBinding;
//   (f) §11-8 v1.1 per-output receiver nonce (U-X3): receiver ciphertext i is
//       encrypted with encryptionNonce + i (EncryptOutputsPerOutputNonce), so
//       both outputs may share an owner (transfer-to-self) without a two-time
//       pad. TRANSFER ONLY — disburse keeps the shared nonce + its
//       duplicate-recipient ban; the authority envelope keeps the plain nonce.
//
// Membership is the append-only IMT (check-imt-proof, depth `nLevels`).
// Everything else (nullifiers, sum/positive checks, authority Poseidon-sponge
// encryption) is unchanged from the zeto non-repudiation base.

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/check-sum.circom";
include "lib/check-nullifiers.circom";
include "check-imt-proof.circom";   // vendored IMT membership (bongtu/circuits/lib, via -l lib)
include "encrypt-outputs-per-output-nonce.circom"; // vendored per-output-nonce receiver encryption (bongtu/circuits/lib, via -l lib)
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/comparators.circom"; // IsZero for the §5.2 zero-commitment belt (also reached transitively via check-imt-proof)
include "node_modules/circomlib/circuits/bitify.circom"; // Num2Bits (kemSs limb canonicalization)
include "node_modules/circomlib/circuits/poseidon.circom"; // hybrid-key / kemBinding derivation (pq-envelope-design.md §2)

template ZetoTransferSmall(nInputs, nOutputs, nLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  signal input inputOwnerPrivateKey;
  signal input ecdhPrivateKey;
  // ML-KEM-768 shared-secret limbs (LE-uint128 halves of ss; PRIVATE).
  signal input kemSs[2];
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

    // §5.2 CRITICAL correction: a zero-commitment input must NEVER be enabled.
    // The index-keyed IMT commits zeros[0]=0 at every padded / ahead-of-frontier
    // index, so 0 is a GENUINE membership-provable leaf — unlike Zeto's value-keyed
    // SMT, where commitment==0 can never be a member. Meanwhile CheckHashes' zero-
    // commitment escape leaves value/salt/owner UNBOUND. Without this belt an attacker
    // spends a padded 0-leaf at enabled=1 with a fresh nullifier and ARBITRARY value X
    // (membership holds, the enabled-belt above is vacuous at enabled=1) => CheckSum
    // mints X from nothing. Forbidding a zero-commitment enabled input restores the
    // SMT's implicit invariant explicitly. Ref spec §5.2.
    var isZeroInputCommitment;
    isZeroInputCommitment = IsZero()(in <== inputCommitments[i]);
    enabled[i] * isZeroInputCommitment === 0;   // enabled=1 => inputCommitment != 0
  }

  // Receiver-decryptable ciphertext (public output — contract binds it directly).
  // Fixed output order (the wallet builder pins it): output 0 = the PAYMENT
  // note (recipient), output 1 = the CHANGE note (sender). Each receiver
  // ciphertext i uses nonce encryptionNonce + i (§11-8 v1.1), so a self-send
  // (payment owner == change owner) does not reuse a sponge keystream; the
  // receiver decrypts ct_i with nonce + i.
  (ecdhPublicKey, cipherTexts) <== EncryptOutputsPerOutputNonce(nOutputs)(ecdhPrivateKey <== ecdhPrivateKey, encryptionNonce <== encryptionNonce, commitmentInputs <== outAuxInputs);

  // Authority (non-repudiation) envelope.
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
}
