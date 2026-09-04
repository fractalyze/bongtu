// Copyright © 2025 Kaleido, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu U2 consumer family, 2026-09-03)
// ---------------------------------------------------
// Derived from circuits/lib/deposit_authority_imt_base.circom (the enterprise
// deposit base, itself derived from Zeto lib/deposit.circom) for the consumer
// (no-auditor) `depositPriv` circuit — OPMOD §2 (.dev/op-module-design.md).
// The enterprise base is NOT edited in place; this is a sibling.
//
// MODIFICATIONS vs deposit_authority_imt_base.circom:
//   (1) NO authority material (OPMOD §2): the arbiter envelope —
//       cipherTextAuthority[l+1], kemBinding, authorityPublicKey[2], the
//       arbiter-side hybrid KDF and its per-op kemSs[2] — is entirely absent.
//   (2) NEW per-output receiver ciphertexts + view tags (OPMOD §3.2/§3.3/§3.5)
//       via ConsumerEncryptOutputs: hybrid (ECDH-to-VIEW-key x ML-KEM-768)
//       receiver key per output, per-output nonce (encryptionNonce + i),
//       canonical 8-bit viewTags via Num2Bits_strict. kemSs becomes a
//       PER-OUTPUT pair of limbs ([nOutputs][2], PRIVATE), and
//       outputViewPublicKeys[nOutputs][2] is a NEW private witness (the
//       view/spend split: commitments keep binding the SPEND key).
//       Enterprise deposit publishes an authority envelope only; the consumer
//       deposit can therefore mint directly to a third party who discovers it
//       by scan.
//
// The stock commitment (CheckHashes) and value-sum (`out`) checks — the
// OPMOD §2.1 CheckPositive + conservation obligations for a 0-input mint —
// are kept verbatim. The input-side complement is applyOp's rootless-mint
// rule (OPMOD §1.3 #2), not a circuit constraint.
//
// Public-signal layout (circom orders outputs first in declaration order, then
// public inputs in declaration order) — OPMOD §2 depositPriv, uint[16]:
//   [0]      out                  (output; = sum of output values, the amount pulled)
//   [1..2]   ecdhPublicKey[2]     (output)
//   [3..10]  cipherTexts[2][4]    (output; receiver-decryptable, one per output)
//   [11..12] viewTags[2]          (output)
//   [13..14] outputCommitments[2] (public input)
//   [15]     encryptionNonce      (public input)   => 16 public signals total.
pragma circom 2.2.2;

include "lib/check-positive.circom";
include "lib/check-hashes.circom";
include "consumer-encrypt-outputs.circom";   // vendored consumer receiver encryption + view tags (bongtu/circuits/lib, via -l lib)

template BongtuConsumerDeposit(nOutputs) {
  // --- public input (via the top-level `public` list) ---
  signal input outputCommitments[nOutputs];
  // --- private inputs ---
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  // note-layer VIEW pubkeys, one per output (OPMOD §3.1) — the receiver-ct
  // encryption target; NEVER the spend key the commitment binds.
  signal input outputViewPublicKeys[nOutputs][2];
  signal input ecdhPrivateKey;
  // ML-KEM-768 shared-secret limbs, one fresh encapsulation per output
  // (LE-uint128 halves of ss_i; PRIVATE — OPMOD §3.3).
  signal input kemSs[nOutputs][2];
  // --- public input ---
  signal input encryptionNonce;

  // --- outputs ---
  signal output out;
  signal output ecdhPublicKey[2];
  signal output cipherTexts[nOutputs][4];
  signal output viewTags[nOutputs];

  // stock deposit: outputs are positive, commitments hash correctly
  // (OPMOD §2.1 REQUIRED: CheckPositive — every output value < 2^100).
  CheckPositive(nOutputs)(outputValues <== outputValues);

  CommitmentInputs() auxInputs[nOutputs];
  for (var i = 0; i < nOutputs; i++) {
    auxInputs[i].value <== outputValues[i];
    auxInputs[i].salt <== outputSalts[i];
    auxInputs[i].ownerPublicKey <== outputOwnerPublicKeys[i];
  }
  CheckHashes(nOutputs)(commitmentHashes <== outputCommitments, commitmentInputs <== auxInputs);

  // sum of output values (the amount pulled from the depositor by the pool) —
  // OPMOD §2.1 REQUIRED conservation: out == Σ output values.
  var sumOutputs = 0;
  for (var i = 0; i < nOutputs; i++) {
    sumOutputs = sumOutputs + outputValues[i];
  }
  out <== sumOutputs;

  // --- consumer receiver encryption + view tags (OPMOD §3) ---
  (ecdhPublicKey, cipherTexts, viewTags) <== ConsumerEncryptOutputs(nOutputs)(
    ecdhPrivateKey <== ecdhPrivateKey,
    encryptionNonce <== encryptionNonce,
    outputViewPublicKeys <== outputViewPublicKeys,
    outputValues <== outputValues,
    outputSalts <== outputSalts,
    kemSs <== kemSs
  );
}
