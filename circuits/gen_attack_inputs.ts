// Extra withdraw fixtures for the U3 soundness tests (SPEC §5.2).
//
// Writes three withdraw witness inputs that the committed prove_all.sh does NOT
// produce, all built from the SHARED fixture_lib.ts material (same SENDER /
// AUTHORITY / salt derivation as gen_inputs.ts by construction):
//
//   withdraw_mint.json    -- the TRUE mint-from-nothing vector: a fabricated input
//       {nullifier=0, commitment=0, value=X, enabled=0} + a zero output => out=X.
//       Post value-belt this is UNSATISFIABLE — `generate_witness` MUST THROW.
//       The contract-derived enabled=(nf!=0)=0 AGREES with the proof, so only the
//       circuit belt closes it. This is the gate (assert_attacks_throw.ts).
//
//   withdraw_attack.json  -- enabled=[1,0] on a VALUE-CARRYING input[1]
//       (nullifier[1] != 0, value[1]=500). Before the belt this proved and was
//       blocked only by the contract's enabled-injection. Post-belt it too is
//       UNSATISFIABLE ((1-enabled[1])*value[1] = 500 != 0) — `generate_witness`
//       MUST THROW, closing the value-carrying forgery at the circuit level.
//
//   withdraw_padded.json  -- a genuine padded slot: input[1] is a zero-value
//       note with nullifier[1]=0, enabled[1]=0. (1-0)*0 = 0 satisfies the belt,
//       so it PROVES and the contract injects enabled[1]=0, matching => ACCEPTED.
//
//   npx tsx gen_attack_inputs.ts

import { commitment, nullifier } from "@bongtu/sdk/note";
import type { WithdrawInput } from "@bongtu/sdk/proving";

import {
  AUTHORITY,
  ECDH_SK,
  ENCRYPTION_NONCE,
  SENDER,
  membership,
  receiver,
  salt,
  write,
} from "./fixture_lib.js";

// §6b v2 authority-envelope material (the shared AUTHORITY key, so
// withdraw_padded encrypts to the SAME arbiter key the contract injects; the two
// throwing fixtures still fail on the value-belt, not on a missing-input error).
const authEnvelope = {
  ecdhPrivateKey: BigInt(ECDH_SK),
  encryptionNonce: ENCRYPTION_NONCE,
  authorityPublicKey: AUTHORITY.publicKey,
};

// --- mint-from-nothing: the TRUE soundness vector (SPEC §5.2) ---------------
// A fabricated input with nullifier=0, commitment=0, value=X, enabled=0 passes
// CheckNullifiers (accepts nf=0 with any value), CheckHashes (accepts commitment=0
// with any value) and CheckIMTProof (enabled=0 skips the root bind), yet CheckSum
// adds its value UNCONDITIONALLY, so out = sumInputs - sumOutputs = X — the pool
// pays X ERC20 against nothing. The contract-derived enabled=(nf!=0)=0 AGREES with
// this proof, so §5.2 contract-injection does NOT catch it. The circuit value-belt
// `(1-enabled)*value===0` DOES: this witness is now unsatisfiable at witness-gen.
// This fixture MUST FAIL `generate_witness` (see assert_attacks_throw.ts).
function genMint(): WithdrawInput {
  const X = 1000n;
  const inValues = [X, 0n]; // input[0] fabricated with value X; input[1] a zero pad
  const inSalts = [salt(30), salt(31)];
  const inCommits = [0n, 0n]; // commitment=0 accepted by CheckHashes with any value
  const { root, pathElements, leafIndices } = membership(inCommits);

  const outValues = [0n]; // a zero output => out = 1000 - 0 = 1000 (minted from nothing)
  const owners = [receiver(0).publicKey];
  const outCommits = [0n];

  return {
    nullifiers: [0n, 0n], // nullifier=0 accepted by CheckNullifiers with any value
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    root,
    pathElements,
    leafIndices,
    enabled: [0n, 0n], // fabricated: membership skipped on both; contract injects the same
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: [salt(0)],
    outputOwnerPublicKeys: owners,
    ...authEnvelope,
  };
}

// --- attack: enabled=[1,0] but input[1] carries value 500 -------------------
function genAttack(): WithdrawInput {
  const inValues = [600n, 500n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const outValues = [100n]; // out = 1100 - 100 = 1000 (inflated by the skipped input)
  const owners = [receiver(0).publicKey];
  const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));

  return {
    nullifiers: inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 0n], // input[1] membership SKIPPED though value-carrying
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    ...authEnvelope,
  };
}

// --- padded: input[1] is a zero note with nullifier 0 -----------------------
function genPadded(): WithdrawInput {
  const inValues = [600n, 0n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const outValues = [100n]; // out = 600 - 100 = 500
  const owners = [receiver(0).publicKey];
  const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));

  return {
    // padded slot: CheckNullifiers accepts nullifier==0 when disabled
    nullifiers: [nullifier(600n, inSalts[0], SENDER.formattedPrivateKey), 0n],
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 0n],
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    ...authEnvelope,
  };
}

write("withdraw_mint", genMint());
write("withdraw_attack", genAttack());
write("withdraw_padded", genPadded());
console.log("mint/attack/padded input generation OK");
