// SPDX-License-Identifier: Apache-2.0
// Uses Zeto circuit libraries (Apache-2.0, © 2024 Kaleido, Inc.) via -l.
pragma circom 2.2.2;
// bongtu production disburse: 1-in / 256-out, IMT depth-32, Poseidon-v1.
// Byte-identical to the proven run_nonrep_imt_256 (same base + public list),
// so the existing 1.24GB zkey / verifier are reused (no fresh setup). The M0
// disburse.circom is the 1x16 dev-loop instantiation of this same base.
include "basetokens/anon_enc_nullifier_non_repudiation_imt_base.circom";
component main { public [ nullifiers, encryptionNonce, root, enabled, authorityPublicKey ] } = Zeto(1, 256, 32);
