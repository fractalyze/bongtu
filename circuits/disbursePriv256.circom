// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu disbursePriv256 (1-in / 256-out): the CONSUMER (no-auditor)
// production batch disburse — OPMOD §2/§4 (.dev/op-module-design.md). Same
// consumer base as the 1x16 dev-loop disbursePriv.circom at depth-8. The 256
// receiver cts and viewTags do NOT ride in the public vector: they travel in
// the module's `disclosure` calldata array (receiverCts[1024] ++ viewTags[256]
// ++ outputCommitments[256] = 1536 elements), totally ordered and bound by the
// EXTENDED disclosureHash fold — which also publishes all 256 output
// commitments, so a PUBLIC indexer can verify fold(leaves) == subtreeRoot and
// fill batch-interior merkle paths with no arbiter key (OPMOD §4.4).
//
// Public (8): [0..1]=ecdhPublicKey [2]=disclosureHash [3]=subtreeRoot
//             [4]=nullifiers[0] [5]=root [6]=enabled[0] [7]=encryptionNonce
// Absent vs enterprise disburse256 (uint[11]): kemBinding,
// authorityPublicKey[2].
//
// Like disburse256, this is NOT in build/prove_all.sh: multi-minute CPU setup,
// GB-scale zkey, GPU proving (the CLAUDE.md GPU regen recipe + witness .so
// rebuild apply when it ships).
include "consumer_disburse_imt_base.circom";

component main { public [ nullifiers, root, enabled, encryptionNonce ] } = BongtuConsumerDisburse(1, 256, 32);
