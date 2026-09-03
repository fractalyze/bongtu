// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu transfer10x2Priv (10-in / 2-out): the CONSUMER (no-auditor)
// consolidation + payment workhorse — OPMOD §2 (.dev/op-module-design.md).
// The SAME consumer base as transferPriv at 10 inputs / 2 outputs: outputs,
// not inputs, are what a spend pays for on chain (docs/circuits.md), so the
// ten-note consolidation lands with exactly the two outputs a spend needs.
// transfer10 is deprecated and gets NO consumer twin.
//
// The base is arity-generic, so every soundness property carries over
// unchanged: the zero-commitment belt and value belt on all 10 inputs, IMT
// membership per enabled input, CheckSum conservation, and the per-output
// receiver nonce (encryptionNonce + i) that makes duplicate output owners
// safe — a merge, where both outputs are the sender's own key, is the point
// of this arity.
//
// Public (36): [0..1]=ecdhPublicKey [2..9]=cipherTexts[2][4]
//              [10..11]=viewTags[2] [12..21]=nullifiers[10] [22]=root
//              [23..32]=enabled[10] (module-injected)
//              [33..34]=outputCommitments[2] [35]=encryptionNonce
// Absent vs enterprise transfer10x2 (uint[68]): cipherTextAuthority[31],
// kemBinding, authorityPublicKey[2]. Added: viewTags[2].
include "consumer_transfer_imt_small_base.circom";

component main {
  public [ nullifiers, root, enabled, outputCommitments, encryptionNonce ]
} = BongtuConsumerTransfer(10, 2, 32);
