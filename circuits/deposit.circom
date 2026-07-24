// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu deposit (0-in / 2-out): stock zeto Deposit(2), reused verbatim.
// Public: outputCommitments + circuit output `out` (= sum of output values).
include "lib/deposit.circom";

component main { public [ outputCommitments ] } = Deposit(2);
