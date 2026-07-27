// Copyright © 2024 Kaleido, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu U-X3 self-send, 2026-07-27)
// -----------------------------------------------
// project-authored, derived from zeto's lib/encrypt-outputs.circom
// (EncryptOutputs). That template encrypts EVERY output's (value, salt) under
// the SAME (ephemeral key, encryptionNonce) pair, so two outputs to the same
// owner share a Poseidon-sponge keystream and leak c1 - c2 = m1 - m2 (the
// §11-8 two-time pad) — which is why transfer-to-self had to be banned.
//
// MODIFICATION vs the original (§11-8 v1.1, TRANSFER ONLY): receiver
// ciphertext i is encrypted with nonce = encryptionNonce + i. Distinct nonces
// give distinct sponge states even under one shared ECDH key, so duplicate
// output owners are safe and the wallet's self-send ban can be lifted. The
// witness shape is untouched (encryptionNonce stays ONE input; the +i offset
// is derived in-circuit), so prover schema / contract call shapes / nPublic
// are all identical — only the constraint system (and hence the vkey) changes.
//
// SymmetricEncrypt constrains each nonce < 2^128; the wallet draws
// encryptionNonce uniform in [0, 2^128) (spend.ts toEncryptionNonce), so
// nonce + i overflows only at encryptionNonce >= 2^128 - (nOutputs-1) — a
// ~2^-127 witness-generation failure, the same negligible class as a salt
// collision.
pragma circom 2.2.2;

include "lib/ecdh.circom";
include "lib/encrypt.circom";
include "node_modules/circomlib/circuits/babyjub.circom";
include "lib/buses.circom";

// EncryptOutputs with a per-output nonce (encryptionNonce + i). One ephemeral
// private key still serves every output's ECDH shared key, exactly as upstream.
template EncryptOutputsPerOutputNonce(nOutputs) {
  signal input ecdhPrivateKey;
  signal input encryptionNonce;
  input CommitmentInputs() commitmentInputs[nOutputs];

  // the public key of the ephemeral private key used in generating ECDH shared keys
  signal output ecdhPublicKey[2];

  // the list of encrypted output UTXO cipher texts
  signal output cipherTexts[nOutputs][4];

  for (var i = 0; i < nOutputs; i++) {
    // generate shared secret
    var sharedSecret[2];
    sharedSecret = Ecdh()(privKey <== ecdhPrivateKey, pubKey <== commitmentInputs[i].ownerPublicKey);

    // encrypt the value for output i under ITS OWN nonce (the §11-8 v1.1 fix)
    cipherTexts[i] <== SymmetricEncrypt(2)(plainText <== [commitmentInputs[i].value, commitmentInputs[i].salt], key <== sharedSecret, nonce <== encryptionNonce + i);
  }

  (ecdhPublicKey[0], ecdhPublicKey[1]) <== BabyPbk()(in <== ecdhPrivateKey);
}
