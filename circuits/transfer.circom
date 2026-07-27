// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transfer (2-in / 2-out): NEW small non-repudiation base with the
// ciphertext re-exposed as public signals (no subtree gadget, no disclosureHash).
//
// Public: [nullifiers[2], outputCommitments[2], encryptionNonce, root,
//          enabled[2], authorityPublicKey[2]]
//         + circuit outputs ecdhPublicKey[2], cipherTexts[2][4],
//           cipherTextAuthority[l+1], kemBinding  => 37 public signals total.
include "anon_enc_nullifier_non_repudiation_imt_small_base.circom";

component main {
  public [ nullifiers, outputCommitments, encryptionNonce, root, enabled, authorityPublicKey ]
} = ZetoTransferSmall(2, 2, 32);
