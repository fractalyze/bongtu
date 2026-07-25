// §5.2 CRITICAL-correction soundness fixture for the DISBURSE base (1-in / 16-out).
//
// disburse's single input is contract-forced enabled=1, so the SMT->IMT zero-leaf
// mint-from-nothing is exploitable by a malicious/compromised discloser: spend a
// padded 0-leaf (commitment 0, genuine zeros-membership) declaring an arbitrary value
// X, and CheckSum mints X into the 16 output notes from nothing. Every OTHER constraint
// is deliberately satisfied so the witness fails on exactly the new belt
// `enabled[i] * IsZero(inputCommitments[i]) === 0` (template Zeto, disburse base).
//
//   npx tsx gen_disburse_zero_leaf.ts   # writes inputs/disburse_zero_leaf.json

import { commitment, nullifier } from "@bongtu/sdk/note";
import type { Point } from "@bongtu/sdk/babyjub";
import type { DisburseInput } from "@bongtu/sdk/proving";

import {
  AUTHORITY,
  ECDH_SK,
  ENCRYPTION_NONCE,
  SENDER,
  ZERO_PATH,
  ZERO_ROOT,
  receiver,
  salt,
  write,
} from "./fixture_lib.js";

const X = 1000000000000n; // 1e12, arbitrary value never deposited

// disburse (Zeto(1,16,32)): single enabled input at a zero commitment.
const N = 16;
// outputs sum to X so CheckSum (equality) passes; only the belt is unsatisfiable.
const outValues = [X, ...Array.from({ length: N - 1 }, () => 0n)];
const owners: Point[] = Array.from({ length: N }, (_, i) => receiver(i).publicKey);
const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));

const obj: DisburseInput = {
  nullifiers: [nullifier(X, salt(30), SENDER.formattedPrivateKey)], // != 0 => contract enabled=1
  inputCommitments: [0n], // CheckHashes escape leaves value unbound
  inputValues: [X],
  inputSalts: [salt(30)],
  inputOwnerPrivateKey: SENDER.formattedPrivateKey,
  ecdhPrivateKey: BigInt(ECDH_SK),
  root: ZERO_ROOT,
  pathElements: [ZERO_PATH],
  leafIndices: [0n], // genuine zeros position, folds to ZERO_ROOT
  enabled: [1n], // enabled at a zero commitment => MUST be UNSATISFIABLE on the belt
  outputCommitments: outCommits,
  outputValues: outValues,
  outputSalts: outValues.map((_, i) => salt(i)),
  outputOwnerPublicKeys: owners,
  encryptionNonce: ENCRYPTION_NONCE,
  authorityPublicKey: AUTHORITY.publicKey,
};

write("disburse_zero_leaf", obj);
