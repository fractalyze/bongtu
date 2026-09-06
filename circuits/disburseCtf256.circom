// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu production ct-free disburse: 1-in / 256-out, IMT depth-32,
// Poseidon-v1 — the CT-FREE sibling of disburse256.circom for the dedicated
// enterprise pool. Same public layout as disburse256 (11 signals); the
// receiver-ct run entering the disclosureHash fold is zero-constrained by the
// base, so the contract's disburseCiphertextLen check and the indexer's
// fold-recompute alarm keep the parent's exact 4·256 ++ authority shape. The
// GB-scale zkey follows the GPU regen recipe (CLAUDE.md) with its matching
// witness .so + w2s pair.
include "ctf_disburse_imt_base.circom";
component main { public [ nullifiers, encryptionNonce, root, enabled, authorityPublicKey ] } = ZetoCtf(1, 256, 32);
