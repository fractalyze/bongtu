// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu disburseCtf (1-in / 16-out): the CT-FREE sibling of disburse.circom
// for the dedicated enterprise pool, at the seconds-per-iteration dev arity.
// Same public layout as disburse (11 signals) — the receiver-ct run entering
// the disclosureHash fold is zero-constrained by the base, so the fold shape,
// the contract's ciphertext-length check, and the indexer's disclosure alarm
// are unchanged. Exercises the subtree gadget and the hybrid authority
// envelope with CPU proving.
//
// Public: [nullifiers, encryptionNonce, root, enabled, authorityPublicKey]
//         + circuit outputs ecdhPublicKey[2], disclosureHash, subtreeRoot,
//           kemBinding  => 11 public signals total.
include "ctf_disburse_imt_base.circom";

component main { public [ nullifiers, encryptionNonce, root, enabled, authorityPublicKey ] } = ZetoCtf(1, 16, 32);
