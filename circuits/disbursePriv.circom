// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu disbursePriv (1-in / 16-out): the CONSUMER (no-auditor) dev-loop
// batch disburse — the OPMOD §2/§4 consumer disburse base instantiated at
// small arity, mirroring the enterprise disburse.circom/disburse256.circom
// pair (OPMOD §9 "consumer dev-loop arity"). Exercises the subtree gadget
// (depth-4), the EXTENDED disclosureHash fold (receiverCts ++ viewTags ++
// outputCommitments, OPMOD §4.2) and the hybrid receiver encryption at
// seconds-per-iteration scale.
//
// Public (8): [0..1]=ecdhPublicKey [2]=disclosureHash [3]=subtreeRoot
//             [4]=nullifiers[0] [5]=root
//             [6]=enabled[0] (module-injected constant 1 after a
//                 ZeroNullifier check — the OPMOD §2.1 module obligation)
//             [7]=encryptionNonce
// Absent vs enterprise disburse (uint[11]): kemBinding, authorityPublicKey[2].
include "consumer_disburse_imt_base.circom";

component main { public [ nullifiers, root, enabled, encryptionNonce ] } = BongtuConsumerDisburse(1, 16, 32);
