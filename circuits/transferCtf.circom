// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transferCtf (2-in / 2-out): the CT-FREE sibling of transfer.circom for
// the dedicated enterprise pool. Same public layout as transfer (37 signals,
// index-identical — the receiver-ct slots are constrained to zero by the base),
// so the verifier ABI and the pool's literal indices are unchanged; only the
// verifying key differs. No receiver-decryptable ciphertext content exists.
//
// Public: [nullifiers[2], outputCommitments[2], encryptionNonce, root,
//          enabled[2], authorityPublicKey[2]]
//         + circuit outputs ecdhPublicKey[2], cipherTexts[2][4] (all zero),
//           cipherTextAuthority[l+1], kemBinding  => 37 public signals total.
include "ctf_transfer_imt_small_base.circom";

component main {
  public [ nullifiers, outputCommitments, encryptionNonce, root, enabled, authorityPublicKey ]
} = ZetoTransferSmallCtf(2, 2, 32);
