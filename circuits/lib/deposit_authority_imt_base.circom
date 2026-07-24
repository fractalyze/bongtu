// Copyright © 2025 Kaleido, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Derived from Zeto (https://github.com/hyperledger-labs/zeto) lib/deposit.circom
// and EXTENDED for bongtu with an in-circuit authority (auditor) envelope, so a
// deposit's output notes are auditor-decryptable from on-chain data alone
// (SPEC §6b v2 "enforced auditor disclosure").
//
// Differences from stock Deposit(nOutputs):
//   (a) new signal inputs ecdhPrivateKey, encryptionNonce, authorityPublicKey[2];
//   (b) new circuit outputs ecdhPublicKey[2] (= BabyPbk(ecdhPrivateKey)) and
//       cipherTextAuthority[l+1] = SymmetricEncrypt over the OUTPUT plaintext
//         [ ownerPub[i].x, ownerPub[i].y  for each output ]
//         [ value[i], salt[i]             for each output ];
//       length 4*nOutputs (10 ct elements at nOutputs=2). Deposit is a mint with
//       no input note, so the envelope covers outputs only.
//   The stock commitment (CheckHashes) and value-sum (`out`) checks are kept
//   verbatim; only the envelope is added.
//
// The contract injects the STORED arbiter pubkey into authorityPublicKey before
// verifying (BongtuPool.deposit), so a proof not encrypted to the current arbiter
// key FAILS — publication is enforced, not merely conventional.
//
// Public-signal layout (circom orders outputs first in declaration order, then
// public inputs in declaration order):
//   [0]      out                     (output; = sum of output values)
//   [1..2]   ecdhPublicKey[2]        (output)
//   [3..12]  cipherTextAuthority[10] (output)
//   [13..14] outputCommitments[2]    (public input)
//   [15]     encryptionNonce         (public input)
//   [16..17] authorityPublicKey[2]   (public input)  => 18 public signals total.
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "lib/ecdh.circom";
include "lib/encrypt.circom";
include "node_modules/circomlib/circuits/babyjub.circom";

template BongtuDepositAuthority(nOutputs) {
  // --- public input (via the top-level `public` list) ---
  signal input outputCommitments[nOutputs];
  // --- private inputs ---
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  signal input ecdhPrivateKey;
  // --- public inputs (contract-injected / auditor-facing) ---
  signal input encryptionNonce;
  signal input authorityPublicKey[2];

  // --- outputs ---
  signal output out;

  // authority (non-repudiation) plaintext length + Poseidon-sponge padding.
  // plaintext = [ownerPub coords x nOutputs] ++ [(value,salt) x nOutputs] = 4*nOutputs.
  var authorityPlainLength = 4 * nOutputs;
  var l = authorityPlainLength;
  if (l % 3 != 0) {
    l += (3 - (l % 3));
  }
  signal output ecdhPublicKey[2];
  signal output cipherTextAuthority[l + 1];

  // stock deposit: outputs are positive, commitments hash correctly.
  CheckPositive(nOutputs)(outputValues <== outputValues);

  CommitmentInputs() auxInputs[nOutputs];
  for (var i = 0; i < nOutputs; i++) {
    auxInputs[i].value <== outputValues[i];
    auxInputs[i].salt <== outputSalts[i];
    auxInputs[i].ownerPublicKey <== outputOwnerPublicKeys[i];
  }
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== auxInputs);

  // sum of output values (the amount pulled from the depositor by the pool).
  var sumOutputs = 0;
  for (var i = 0; i < nOutputs; i++) {
    sumOutputs = sumOutputs + outputValues[i];
  }
  out <== sumOutputs;

  // --- authority envelope (auditor-decryptable) ---
  (ecdhPublicKey[0], ecdhPublicKey[1]) <== BabyPbk()(in <== ecdhPrivateKey);

  var sharedSecretAuthority[2];
  (sharedSecretAuthority) = Ecdh()(privKey <== ecdhPrivateKey, pubKey <== authorityPublicKey);

  var plainText[4 * nOutputs];
  var idx = 0;
  for (var i = 0; i < nOutputs; i++) {
    plainText[idx] = outputOwnerPublicKeys[i][0];
    idx++;
    plainText[idx] = outputOwnerPublicKeys[i][1];
    idx++;
  }
  for (var i = 0; i < nOutputs; i++) {
    plainText[idx] = outputValues[i];
    idx++;
    plainText[idx] = outputSalts[i];
    idx++;
  }

  cipherTextAuthority <== SymmetricEncrypt(4 * nOutputs)(plainText <== plainText, key <== sharedSecretAuthority, nonce <== encryptionNonce);
}
