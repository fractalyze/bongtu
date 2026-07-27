// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// bongtu disburse (1-in / 16-out): the existing zeto IMT non-repudiation base
// instantiated at small batch size, mirroring run_nonrep_imt_256.circom but with
// nOutputs = 16. Exercises the subtree gadget (depth-4), disclosureHash, and
// authority encryption at seconds-per-iteration scale.
//
// Public: [nullifiers, encryptionNonce, root, enabled, authorityPublicKey]
//         + circuit outputs ecdhPublicKey[2], disclosureHash, subtreeRoot,
//           kemBinding  => 11 public signals total.
// Base is the VENDORED copy in circuits/lib (resolves via `-l lib`); a fresh
// checkout no longer depends on any untracked zeto file (docs/zeto-derivation.md).
include "anon_enc_nullifier_non_repudiation_imt_base.circom";

component main { public [ nullifiers, encryptionNonce, root, enabled, authorityPublicKey ] } = Zeto(1, 16, 32);
