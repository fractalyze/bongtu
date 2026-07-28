// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transfer10x2 (10-in / 2-out): the SAME small non-repudiation base as
// transfer.circom and transfer10.circom, instantiated at 10 inputs but only TWO
// outputs. It exists because output arity is what a spend PAYS FOR on chain: a
// 10-out spend appends ten depth-32 IMT leaves (~9.3M of transfer10's measured
// 11.59M gas), and eight of them are zero-value padding on every real spend. At
// 10x2 the two outputs are exactly the two a spend actually needs — output 0 is
// the payment (or, for a pure merge, the merged note) and output 1 is the change
// (zero when there is nothing left over) — so the same 10-note consolidation
// lands for ~3M.
//
// transfer10 stays deployed; this is an ADDITIONAL circuit, not a replacement.
// No base change — `ZetoTransferSmall` is arity-generic, so every soundness
// property carries over unchanged: the zero-commitment belt and value belt on
// all 10 inputs, IMT membership per enabled input, CheckSum conservation, the
// hybrid (ECDH || ML-KEM) authority envelope + kemBinding, and the §11-8 v1.1
// per-output receiver nonce (encryptionNonce + i) that makes duplicate output
// owners safe — a merge, where both outputs are the sender's own key, is the
// point of this arity.
//
// Public: [nullifiers[10], root, enabled[10], outputCommitments[2],
//          encryptionNonce, authorityPublicKey[2]]           (26 public inputs)
//         + circuit outputs ecdhPublicKey[2], cipherTexts[2][4],
//           cipherTextAuthority[31], kemBinding              (42 outputs)
//         => 68 public signals total. Index map: docs/circuits.md.
include "anon_enc_nullifier_non_repudiation_imt_small_base.circom";

component main {
  public [ nullifiers, outputCommitments, encryptionNonce, root, enabled, authorityPublicKey ]
} = ZetoTransferSmall(10, 2, 32);
