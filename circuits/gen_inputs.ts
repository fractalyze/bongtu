// Deterministic witness-input generator for the 4 bongtu M0 circuits.
//
// Builds each circuit's input.json from the U1 SDK: real ImtTree membership
// witnesses (root + pathElements + leafIndices), poseidon commitments /
// nullifiers, and the two-time-pad dup-owner guard. The fixed key material,
// membership(), and write() live in fixture_lib.ts (shared by all five
// generators; PRNG-free, so fixtures are reproducible).
//
//   npx tsx gen_inputs.ts        # writes inputs/{deposit,disburse,transfer,withdraw}.json
//
// Each generator's return value is typed with the @bongtu/sdk/proving input
// interface its circuit consumes, so the root tsc gate enforces that the
// committed fixtures agree with the shared ProvingRequest wire types
// (prover/prover_service/schema.py round-trips the same files from Python).

import { commitment, nullifier, assertDistinctOwnerPubkeys } from "@bongtu/sdk/note";
import type { Point } from "@bongtu/sdk/babyjub";
import type {
  DepositInput,
  DisburseInput,
  TransferInput,
  WithdrawInput,
} from "@bongtu/sdk/proving";

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
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
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
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

write("deposit", genDeposit());
write("disburse", genDisburse());
write("transfer", genTransfer());
write("withdraw", genWithdraw());
console.log("input generation OK");
