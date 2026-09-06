// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transfer10x2Ctf (10-in / 2-out): the CT-FREE sibling of
// transfer10x2.circom for the dedicated enterprise pool. Same public layout as
// transfer10x2 (68 signals, index-identical — receiver-ct slots
// zero-constrained by the base), same consolidation economics as the parent.
// No receiver-decryptable ciphertext content exists.
//
// Public: [nullifiers[10], root, enabled[10], outputCommitments[2],
//          encryptionNonce, authorityPublicKey[2]]           (26 public inputs)
//         + circuit outputs ecdhPublicKey[2], cipherTexts[2][4] (all zero),
//           cipherTextAuthority[31], kemBinding              (42 outputs)
//         => 68 public signals total.
include "ctf_transfer_imt_small_base.circom";

component main {
  public [ nullifiers, outputCommitments, encryptionNonce, root, enabled, authorityPublicKey ]
} = ZetoTransferSmallCtf(10, 2, 32);
