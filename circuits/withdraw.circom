// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu withdraw (2-in / 1-out): withdraw_nullifier rebased onto the append-only
// IMT (depth 32), comparator widened to GreaterEqThan(101), PLUS an in-circuit
// authority (auditor) envelope (SPEC §6b v2) so the spent inputs + change note
// are auditor-decryptable from on-chain data alone.
//
// Public (25): [0]=out [1..2]=ecdhPublicKey [3..15]=cipherTextAuthority[13]
//              [16..17]=nullifiers [18]=root [19..20]=enabled
//              [21]=outputCommitments[0] [22]=encryptionNonce
//              [23..24]=authorityPublicKey
include "check-nullifiers-value-imt-base.circom";

component main {
  public [ nullifiers, root, enabled, outputCommitments, encryptionNonce, authorityPublicKey ]
} = CheckNullifiersInputsOutputsValueIMT(2, 1, 32);
