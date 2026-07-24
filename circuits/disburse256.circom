// SPDX-License-Identifier: Apache-2.0
// Uses Zeto circuit libraries (Apache-2.0, © 2024 Kaleido, Inc.) via -l.
pragma circom 2.2.2;
// bongtu production disburse: 1-in / 256-out, IMT depth-32, Poseidon-v1.
// Instantiates the same VENDORED base as the 1x16 dev-loop disburse.circom
// (circuits/lib, resolved via `-l lib`; a fresh checkout no longer depends on any
// untracked zeto file — docs/zeto-derivation.md). Supersedes the untracked
// run_nonrep_imt_256.circom top-level. NOTE: the §5.2 zero-commitment belt now in
// the base changes the r1cs, so the 1.24GB GPU zkey / verifier must be regenerated
// (byte-identity reuse retired — the main loop does the 256-arity GPU setup).
include "anon_enc_nullifier_non_repudiation_imt_base.circom";
component main { public [ nullifiers, encryptionNonce, root, enabled, authorityPublicKey ] } = Zeto(1, 256, 32);
