// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transferPriv (2-in / 2-out): the CONSUMER (no-auditor) transfer —
// OPMOD §2 (.dev/op-module-design.md). Same input-side soundness belts as the
// enterprise transfer (enabled boolean + value belt + zero-commitment guard +
// IMT membership + CheckSum), NO authority material, and the receiver
// ciphertexts re-keyed to the hybrid (VIEW-key ECDH x ML-KEM-768) consumer
// construction with NEW canonical viewTags (OPMOD §3).
//
// Public (20): [0..1]=ecdhPublicKey [2..9]=cipherTexts[2][4]
//              [10..11]=viewTags[2] [12..13]=nullifiers[2] [14]=root
//              [15..16]=enabled[2] (module-injected: nullifier[i] != 0)
//              [17..18]=outputCommitments[2] [19]=encryptionNonce
// Absent vs enterprise transfer (uint[37]): cipherTextAuthority[16],
// kemBinding, authorityPublicKey[2]. Added: viewTags[2].
include "consumer_transfer_imt_small_base.circom";

component main {
  public [ nullifiers, root, enabled, outputCommitments, encryptionNonce ]
} = BongtuConsumerTransfer(2, 2, 32);
