// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu withdraw (2-in / 1-out): withdraw_nullifier rebased onto the append-only
// IMT (depth 32), comparator widened to GreaterEqThan(101), PLUS an in-circuit
// authority (auditor) envelope (SPEC §6b v2) so the spent inputs + change note
// are auditor-decryptable from on-chain data alone.
//
// Public (26): [0]=out [1..2]=ecdhPublicKey [3..15]=cipherTextAuthority[13]
//              [16]=kemBinding [17..18]=nullifiers [19]=root [20..21]=enabled
//              [22]=outputCommitments[0] [23]=encryptionNonce
//              [24..25]=authorityPublicKey
include "check-nullifiers-value-imt-base.circom";

component main {
  public [ nullifiers, root, enabled, outputCommitments, encryptionNonce, authorityPublicKey ]
} = CheckNullifiersInputsOutputsValueIMT(2, 1, 32);
