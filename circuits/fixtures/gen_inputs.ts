// Deterministic witness-input generator for the 4 bongtu M0 circuits.
//
// Builds each circuit's input.json from the U1 SDK: real ImtTree membership
// witnesses (root + pathElements + leafIndices), poseidon commitments /
// nullifiers, and the two-time-pad dup-owner guard. The fixed key material,
// membership(), and write() live in fixture_lib.ts (shared by all five
// generators; PRNG-free, so fixtures are reproducible).
//
//   npx tsx circuits/fixtures/gen_inputs.ts        # writes one fixtures/inputs/<fixture>.json per write() below
//
// Each generator's return value is typed with the @bongtu/core/proving input
// interface its circuit consumes, so the root tsc gate enforces that the
// committed fixtures agree with the shared ProvingRequest wire types
// (prover/prover_service/schema.py round-trips the same files from Python).

import { commitment, nullifier, assertDistinctOwnerPubkeys } from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";
import type {
  DepositInput,
  DisburseInput,
  Transfer10Input,
  Transfer10x2Input,
  TransferInput,
  WithdrawInput,
} from "@bongtu/core/proving";

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

// --- deposit (0-in / 2-out), stock Deposit(2) ------------------------------

function genDeposit(): DepositInput {
  const values = [1000n, 2000n];
  const owners: Point[] = values.map((_, i) => receiver(i).publicKey);
  assertDistinctOwnerPubkeys(owners);
  const outputCommitments = values.map((v, i) => commitment(v, salt(i), owners[i]));
  return {
    outputCommitments,
    outputValues: values,
    outputSalts: values.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    // §6b v2 auditor envelope (outputs-only; deposit is a mint, no input note).
    ecdhPrivateKey: BigInt(ECDH_SK),
    kemSs: kemDraw("deposit").kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

// --- disburse (1-in / 16-out), Zeto(1,16,32) -------------------------------

function genDisburse(): DisburseInput {
  const N = 16;
  const inValue = 1600n;
  const inSalt = salt(99);
  const inCommit = commitment(inValue, inSalt, SENDER.publicKey);
  const { root, pathElements, leafIndices } = membership([inCommit]);

  const outValues = Array.from({ length: N }, () => 100n); // 16 * 100 == 1600
  const owners: Point[] = Array.from({ length: N }, (_, i) => receiver(i).publicKey);
  assertDistinctOwnerPubkeys(owners); // §4 two-time-pad guard (shared ephemeral key)
  const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));

  return {
    nullifiers: [nullifier(inValue, inSalt, SENDER.formattedPrivateKey)],
    inputCommitments: [inCommit],
    inputValues: [inValue],
    inputSalts: [inSalt],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [1n],
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    kemSs: kemDraw("disburse").kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

// --- transfer (2-in / 2-out), ZetoTransferSmall(2,2,32) --------------------

function genTransfer(): TransferInput {
  const inValues = [700n, 300n];
  const inSalts = [salt(10), salt(11)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const outValues = [600n, 400n]; // sum 1000 == 700 + 300
  const owners: Point[] = [receiver(0).publicKey, receiver(1).publicKey];
  // Fixture hygiene, not a protocol rule (transfer allows duplicates since §11-8
  // v1.1): the canonical fixture stays distinct-recipient so auditor_decrypt_check
  // exercises two different recipient keys and regen stays byte-stable.
  assertDistinctOwnerPubkeys(owners);
  const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));

  return {
    nullifiers: inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 1n],
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    kemSs: kemDraw("transfer").kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

// --- the 10-input transfer arities, ZetoTransferSmall(10, nOut, 32) ---------
//
// Two circuits share this input side: transfer10 (10 outputs) and transfer10x2
// (2 outputs). Only `nOut` differs, so one builder produces both.

// Padding convention, mirrored from the wallet's spend assembler: an unused
// input slot carries nullifier 0, value 0, enabled 0, a zeros path and a
// NONZERO value-0 commitment owned by the sender (a zero commitment at
// enabled=0 would be legal but pointless, and at enabled=1 the §5.2 belt
// forbids it outright). An unused output slot is a real value-0 note.
const ZEROS_PATH = Array.from({ length: H }, () => 0n);

function padInput(i: number): {
  nullifier: bigint;
  commitment: bigint;
  value: bigint;
  salt: bigint;
} {
  const s = salt(80 + i);
  return { nullifier: 0n, commitment: commitment(0n, s, SENDER.publicKey), value: 0n, salt: s };
}

/** Build a 10-input transfer witness from `inValues` real inputs (padded out to
 *  10) and `outputs` real outputs (padded out to `nOut` with value-0 self
 *  notes). Value conservation is asserted here, not left to the circuit to
 *  discover. The return shape is the same for both output arities — the callers
 *  name it Transfer10Input or Transfer10x2Input. */
function spend10(
  label: string,
  nOut: number,
  inValues: bigint[],
  inSaltBase: number,
  outputs: { value: bigint; owner: Point }[],
  outSaltBase: number,
): Transfer10Input {
  const N = 10;
  if (inValues.length > N) throw new Error(`${label}: input arity is 10`);
  if (outputs.length > nOut) throw new Error(`${label}: output arity is ${nOut}`);

  const inSalts = inValues.map((_, i) => salt(inSaltBase + i));
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const pads = Array.from({ length: N - inValues.length }, (_, i) => padInput(i));
  const allNullifiers = [
    ...inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
    ...pads.map((p) => p.nullifier),
  ];

  // Unused output slots: value-0 notes back to the sender. Duplicate output
  // owners are SAFE here (§11-8 v1.1 per-output nonce) and unavoidable at these
  // arities — hence no assertDistinctOwnerPubkeys, unlike the disburse fixture.
  const outAll = [
    ...outputs,
    ...Array.from({ length: nOut - outputs.length }, () => ({ value: 0n, owner: SENDER.publicKey })),
  ];
  const outSalts = outAll.map((_, i) => salt(outSaltBase + i));

  const inSum = inValues.reduce((a, v) => a + v, 0n);
  const outSum = outAll.reduce((a, o) => a + o.value, 0n);
  if (inSum !== outSum) throw new Error(`${label}: value not conserved (${inSum} != ${outSum})`);

  return {
    nullifiers: allNullifiers,
    inputCommitments: [...inCommits, ...pads.map((p) => p.commitment)],
    inputValues: [...inValues, ...pads.map((p) => p.value)],
    inputSalts: [...inSalts, ...pads.map((p) => p.salt)],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements: [...pathElements, ...pads.map(() => ZEROS_PATH)],
    leafIndices: [...leafIndices, ...pads.map(() => 0n)],
    enabled: [...inValues.map(() => 1n), ...pads.map(() => 0n)],
    outputCommitments: outAll.map((o, i) => commitment(o.value, outSalts[i], o.owner)),
    outputValues: outAll.map((o) => o.value),
    outputSalts: outSalts,
    outputOwnerPublicKeys: outAll.map((o) => o.owner),
    kemSs: kemDraw(label).kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

/** The canonical partly-filled case: 4 real inputs + 6 pads, 2 real outputs
 *  (payment + change) + 8 zero pads — the shape a wallet produces when it picks
 *  four notes to cover one payment. */
function genTransfer10(): Transfer10Input {
  return spend10(
    "transfer10",
    10,
    [400n, 300n, 200n, 100n], // 1000 spendable
    40,
    [
      { value: 700n, owner: receiver(0).publicKey }, // payment
      { value: 300n, owner: SENDER.publicKey }, // change
    ],
    50,
  );
}

/** The full-arity consolidation: all 10 input slots real, merged into ONE
 *  self-owned output (the remaining 9 are value-0 self notes). Every output
 *  owner is the same key — the duplicate-owner case the shared-nonce circuits
 *  ban and the per-output nonce makes safe. */
function genTransfer10Consolidate(): Transfer10Input {
  const inValues = Array.from({ length: 10 }, (_, i) => BigInt(100 * (i + 1))); // 5500
  return spend10(
    "transfer10_consolidate",
    10,
    inValues,
    60,
    [{ value: 5500n, owner: SENDER.publicKey }],
    70,
  );
}

// --- transfer10x2 (10-in / 2-out), ZetoTransferSmall(10,2,32) ---------------

/** The canonical partly-filled case at 2 outputs: 4 real inputs + 6 pads paying
 *  one distinct payee, change back to the sender. The same spend as the
 *  transfer10 fixture, minus the eight zero-value output slots it had to append
 *  to the tree anyway. */
function genTransfer10x2(): Transfer10x2Input {
  return spend10(
    "transfer10x2",
    2,
    [400n, 300n, 200n, 100n], // 1000 spendable
    100,
    [
      { value: 700n, owner: receiver(0).publicKey }, // payment
      { value: 300n, owner: SENDER.publicKey }, // change
    ],
    110,
  );
}

/** The pure merge — the shape the wallet's spend chain uses: all 10 input slots
 *  real, output 0 the merged total back to self, output 1 a ZERO-value change
 *  note (also self). Both outputs share ONE owner, the duplicate-owner case the
 *  shared-nonce circuits ban and the §11-8 v1.1 per-output nonce makes safe. */
function genTransfer10x2Merge(): Transfer10x2Input {
  const inValues = Array.from({ length: 10 }, (_, i) => BigInt(100 * (i + 1))); // 5500
  return spend10(
    "transfer10x2_merge",
    2,
    inValues,
    120,
    [{ value: 5500n, owner: SENDER.publicKey }], // output 1 pads to a zero self note
    130,
  );
}

// --- withdraw (2-in / 1-out), CheckNullifiersInputsOutputsValueIMT(2,1,32) --

function genWithdraw(): WithdrawInput {
  const inValues = [600n, 500n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const outValues = [100n]; // change; withdrawn amount out = 1100 - 100 = 1000
  const owners: Point[] = [receiver(0).publicKey];
  assertDistinctOwnerPubkeys(owners);
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
    enabled: [1n, 1n],
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    // §6b v2 auditor envelope (input owner + inputs + change note).
    ecdhPrivateKey: BigInt(ECDH_SK),
    kemSs: kemDraw("withdraw").kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

write("deposit", genDeposit());
write("disburse", genDisburse());
write("transfer", genTransfer());
write("transfer10", genTransfer10());
write("transfer10_consolidate", genTransfer10Consolidate());
write("transfer10x2", genTransfer10x2());
write("transfer10x2_merge", genTransfer10x2Merge());
write("withdraw", genWithdraw());
console.log("input generation OK");
