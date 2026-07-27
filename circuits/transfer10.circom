// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transfer10 (10-in / 10-out): the SAME small non-repudiation base as
// transfer.circom, instantiated at arity 10 so one tx can consolidate up to ten
// notes (the 2-in ceiling forced a chain of self-sends to merge dust) and fan
// out to ten payees. No base change — `ZetoTransferSmall` is arity-generic, so
// every soundness property carries over unchanged: the zero-commitment belt and
// value belt on all 10 inputs, IMT membership per enabled input, CheckSum
// conservation, the hybrid (ECDH || ML-KEM) authority envelope + kemBinding, and
// the §11-8 v1.1 per-output receiver nonce (encryptionNonce + i) that makes
// duplicate output owners safe — self-merge, where every output is the sender's
// own key, is the point of this arity.
//
// Public: [nullifiers[10], root, enabled[10], outputCommitments[10],
//          encryptionNonce, authorityPublicKey[2]]           (34 public inputs)
//         + circuit outputs ecdhPublicKey[2], cipherTexts[10][4],
//           cipherTextAuthority[64], kemBinding              (107 outputs)
//         => 141 public signals total. Index map: docs/circuits.md.
include "anon_enc_nullifier_non_repudiation_imt_small_base.circom";

component main {
  public [ nullifiers, outputCommitments, encryptionNonce, root, enabled, authorityPublicKey ]
} = ZetoTransferSmall(10, 10, 32);
