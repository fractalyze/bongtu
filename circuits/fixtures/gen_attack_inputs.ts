// Extra value-belt fixtures for the U3 soundness tests (SPEC §5.2).
//
// Writes five witness inputs that the committed prove_all.sh does NOT produce,
// all built from the SHARED fixture_lib.ts material (same SENDER / AUTHORITY /
// salt derivation as gen_inputs.ts by construction):
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
//   transfer10_attack.json / transfer10x2_attack.json -- the same value-carrying
//       disabled slot on the two 10-input circuits, where legitimate disabled
//       pads are the norm rather than the exception. Also UNSATISFIABLE —
//       `generate_witness` MUST THROW.
//
//   npx tsx circuits/fixtures/gen_attack_inputs.ts

import { commitment, nullifier } from "@bongtu/core/note";
import type { Transfer10Input, WithdrawInput } from "@bongtu/core/proving";

import {
  AUTHORITY,
  ECDH_SK,
  ENCRYPTION_NONCE,
  H,
  SENDER,
  kemDraw,
  membership,
  receiver,
  salt,
  write,
} from "./fixture_lib.js";

// §6b v2 authority-envelope material (the shared AUTHORITY key, so
// withdraw_padded encrypts to the SAME arbiter key the contract injects; the two
// throwing fixtures still fail on the value-belt, not on a missing-input error).
const authEnvelope = (label: string) => ({
  ecdhPrivateKey: BigInt(ECDH_SK),
  kemSs: kemDraw(label).kemSs,
  encryptionNonce: ENCRYPTION_NONCE,
  authorityPublicKey: AUTHORITY.publicKey,
});

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
    ...authEnvelope("withdraw_mint"),
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
    ...authEnvelope("withdraw_attack"),
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
    ...authEnvelope("withdraw_padded"),
  };
}

// --- 10-input attack: a value-carrying input in a DISABLED slot -------------
// The 10-input twin of genAttack, built for both output arities. At arity 2 a
// value-carrying disabled slot is conspicuous; at 10 inputs most slots are
// legitimately disabled pads, so this is where a value belt that only guarded
// the first slots would let a spend inflate itself. Slot 4 carries 500 at
// enabled=0, so CheckSum totals 1500 against 1000 of real inputs —
// `(1 - enabled[4]) * inputValues[4] = 500 != 0` must make the witness
// unsatisfiable. The honest transfer10 / transfer10x2 fixtures (zero-value
// disabled pads) are the positive controls that the belt does not reject real
// padding.
function genSpend10Attack(label: string, nOut: number): Transfer10Input {
  const N = 10;
  const real = [400n, 300n, 200n, 100n]; // enabled, 1000 total
  const smuggled = 500n; // slot 4: value-carrying but enabled=0
  const inValues = [...real, smuggled];
  const inSalts = inValues.map((_, i) => salt(40 + i));
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  // Pads occupy the tail: zero value, zero nullifier, nonzero value-0 commitment.
  const nPad = N - inValues.length;
  const padSalts = Array.from({ length: nPad }, (_, i) => salt(80 + i));
  const zerosPath = Array.from({ length: H }, () => 0n);

  const outValues = Array.from({ length: nOut }, (_, i) => (i === 0 ? 1500n : 0n)); // inflated
  const owners = Array.from({ length: nOut }, (_, i) =>
    i === 0 ? receiver(0).publicKey : SENDER.publicKey,
  );

  return {
    nullifiers: [
      ...inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
      ...padSalts.map(() => 0n),
    ],
    inputCommitments: [...inCommits, ...padSalts.map((s) => commitment(0n, s, SENDER.publicKey))],
    inputValues: [...inValues, ...padSalts.map(() => 0n)],
    inputSalts: [...inSalts, ...padSalts],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    root,
    pathElements: [...pathElements, ...padSalts.map(() => zerosPath)],
    leafIndices: [...leafIndices, ...padSalts.map(() => 0n)],
    enabled: [1n, 1n, 1n, 1n, 0n, ...padSalts.map(() => 0n)], // slot 4 skipped though value-carrying
    outputCommitments: outValues.map((v, i) => commitment(v, salt(50 + i), owners[i])),
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(50 + i)),
    outputOwnerPublicKeys: owners,
    ...authEnvelope(label),
  };
}

write("withdraw_mint", genMint());
write("withdraw_attack", genAttack());
write("withdraw_padded", genPadded());
write("transfer10_attack", genSpend10Attack("transfer10_attack", 10));
write("transfer10x2_attack", genSpend10Attack("transfer10x2_attack", 2));
console.log("mint/attack/padded input generation OK");
