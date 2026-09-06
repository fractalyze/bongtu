// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transfer10Ctf (10-in / 10-out): the CT-FREE sibling of transfer10.circom
// for the dedicated enterprise pool. Same public layout as transfer10 (141
// signals, index-identical — receiver-ct slots zero-constrained by the base).
// It exists to fill the pool's mandatory Transfer10Verifier slot with a ct-free
// verifier: wiring the stock ct-carrying one would leave a receiver-ct escape
// hatch on the dedicated pool. The circuit stays deprecated for clients exactly
// like its parent (the spend-chain deprecation pins are untouched).
//
// Public: [nullifiers[10], root, enabled[10], outputCommitments[10],
//          encryptionNonce, authorityPublicKey[2]]           (34 public inputs)
//         + circuit outputs ecdhPublicKey[2], cipherTexts[10][4] (all zero),
//           cipherTextAuthority[64], kemBinding              (107 outputs)
//         => 141 public signals total.
include "ctf_transfer_imt_small_base.circom";

component main {
  public [ nullifiers, outputCommitments, encryptionNonce, root, enabled, authorityPublicKey ]
} = ZetoTransferSmallCtf(10, 10, 32);
