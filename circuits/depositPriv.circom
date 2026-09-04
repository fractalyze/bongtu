// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu depositPriv (0-in / 2-out): the CONSUMER (no-auditor) deposit —
// OPMOD §2 (.dev/op-module-design.md). Stock zeto Deposit(2) commitment/sum
// checks PLUS per-output hybrid receiver ciphertexts and canonical view tags,
// and NO authority material (no cipherTextAuthority, no kemBinding, no
// authorityPublicKey — there is no arbiter in this family). A consumer deposit
// can therefore mint directly to a third party, who discovers it by scan
// (viewTag filter -> Decaps -> decrypt -> leaf-match).
//
// Public (16): [0]=out [1..2]=ecdhPublicKey [3..10]=cipherTexts[2][4]
//              [11..12]=viewTags[2] [13..14]=outputCommitments[2]
//              [15]=encryptionNonce
// Absent vs enterprise deposit (uint[19]): cipherTextAuthority[10],
// kemBinding, authorityPublicKey[2]. Added: cipherTexts[2][4], viewTags[2].
include "consumer_deposit_imt_base.circom";

component main {
  public [ outputCommitments, encryptionNonce ]
} = BongtuConsumerDeposit(2);
