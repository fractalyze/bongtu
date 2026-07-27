// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu deposit (0-in / 2-out): stock zeto Deposit(2) commitment/sum checks
// PLUS an in-circuit authority (auditor) envelope so the minted output notes are
// auditor-decryptable from on-chain data alone (SPEC §6b v2). The contract injects
// the stored arbiter pubkey into authorityPublicKey, so a proof not encrypted to
// the current arbiter key FAILS.
//
// Public (19): [0]=out [1..2]=ecdhPublicKey [3..12]=cipherTextAuthority[10]
//              [13]=kemBinding [14..15]=outputCommitments [16]=encryptionNonce
//              [17..18]=authorityPublicKey
include "deposit_authority_imt_base.circom";

component main {
  public [ outputCommitments, encryptionNonce, authorityPublicKey ]
} = BongtuDepositAuthority(2);
