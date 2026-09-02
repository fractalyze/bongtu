// §5.2 CRITICAL-correction soundness fixtures: the zero-leaf spend.
//
// The SMT->IMT swap reopened a SECOND, distinct mint-from-nothing that the earlier
// value-belt `(1-enabled)*value===0` does NOT cover, because the exploit runs at
// enabled=1 (where that belt is vacuous):
//
//   input0 = { commitment: 0, value: X (arbitrary), salt: any, sk: attacker,
//              leafIndex: a zeros position, path: genuine zeros siblings,
//              enabled: 1, nullifier: Poseidon3(X,salt,sk) != 0 }
//
// In the index-keyed IMT, zeros[0]=0 is a GENUINE membership-provable leaf at every
// padded / ahead-of-frontier index (here index 0 of an empty tree, root == zeros[H],
// siblings == zeros[0..H-1] — folding a 0-leaf reproduces the empty root). CheckHashes'
// zero-commitment escape leaves value UNBOUND, CheckNullifiers binds the fresh nonzero
// nullifier, membership holds at enabled=1, CheckSum then yields the attacker's X from
// nothing => a permissionless withdraw/transfer drain (see
// [[imt-membership-breaks-zeto-zero-commitment-escape]]).
//
// Every OTHER constraint is deliberately satisfied so the witness fails on exactly the
// new belt `enabled[i] * IsZero(inputCommitments[i]) === 0` and nothing else — the
// assertion string then names the spending base template. The shared material
// (SENDER / AUTHORITY / zeros path) comes from fixture_lib.ts. Run through tsx:
//
//   npx tsx circuits/fixtures/gen_zero_leaf_inputs.ts   # writes fixtures/inputs/{transfer,transfer10,transfer10x2,withdraw}_zero_leaf.json

import { commitment, nullifier } from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";
import type { Transfer10Input, TransferInput, WithdrawInput } from "@bongtu/core/proving";

import {
  AUTHORITY,
  ECDH_SK,
  ENCRYPTION_NONCE,
  SENDER,
  ZERO_PATH,
  ZERO_ROOT,
  kemDraw,
  receiver,
  salt,
  write,
} from "./fixture_lib.js";

// The arbitrary value the attacker mints from a padded 0-leaf they never deposited.
// Well within the stock 100-bit range so CheckPositive/GreaterEqThan witness-gen
// succeeds and the ONLY unsatisfiable constraint is the new zero-commitment belt.
const X = 1000000000000n; // 1e12

// input0 across both circuits: the exploit (commitment 0, value X, enabled 1, fresh nf).
const exploitInput0 = {
  nullifier: nullifier(X, salt(30), SENDER.formattedPrivateKey), // != 0 => contract-enabled=1
  commitment: 0n, // CheckHashes escape leaves value unbound
  value: X, // arbitrary — never deposited
  salt: salt(30),
  leafIndex: 0n, // a genuine zeros position
  path: ZERO_PATH,
};

// input1 across both circuits: a genuine DISABLED pad (commitment 0, value 0, nf 0,
// enabled 0). The new belt is vacuous here (enabled=0 => 0*IsZero=0), so the pad
// alone does NOT trip the constraint — only input0 does.
const padInput1 = {
  nullifier: 0n,
  commitment: 0n,
  value: 0n,
  salt: salt(31),
  leafIndex: 0n,
  path: ZERO_PATH,
};

// --- transfer (2-in / 2-out): outputs sum to X so CheckSum (equality) passes -------
function genTransferZeroLeaf(): TransferInput {
  const outValues = [X, 0n]; // sum == X == sumInputs (X + 0)
  const owners: Point[] = [receiver(0).publicKey, receiver(1).publicKey];
  const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));
  return {
    nullifiers: [exploitInput0.nullifier, padInput1.nullifier],
    inputCommitments: [exploitInput0.commitment, padInput1.commitment],
    inputValues: [exploitInput0.value, padInput1.value],
    inputSalts: [exploitInput0.salt, padInput1.salt],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root: ZERO_ROOT,
    pathElements: [exploitInput0.path, padInput1.path],
    leafIndices: [exploitInput0.leafIndex, padInput1.leafIndex],
    enabled: [1n, 0n], // input0 enabled at a zero commitment => must be UNSATISFIABLE
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    kemSs: kemDraw("transfer_zero_leaf").kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

// --- the 10-in circuits: the exploit hides in a PADDED slot ------------------------
// At arity 10 most slots are padding on a typical spend, so slot 0 is the LEAST
// interesting place to look: the exploit sits at slot 7, surrounded by genuine
// disabled pads, and the belt must still reject it. (The belt is a per-slot
// loop, so a slot-0-only fixture would leave nine unproven slots.) The input
// side is identical for transfer10 and transfer10x2, so one builder covers both
// — only the output count differs.
const EXPLOIT_SLOT = 7;

function genSpend10ZeroLeaf(label: string, nOut: number): Transfer10Input {
  const N = 10;
  const slot = <T>(exploit: T, pad: T): T[] =>
    Array.from({ length: N }, (_, i) => (i === EXPLOIT_SLOT ? exploit : pad));

  // Every output but the first is a value-0 self note, so CheckSum's equality
  // holds at sum == X and the ONLY unsatisfiable constraint is the belt.
  const outValues = Array.from({ length: nOut }, (_, i) => (i === 0 ? X : 0n));
  const owners: Point[] = Array.from({ length: nOut }, (_, i) => receiver(i % 2).publicKey);
  return {
    nullifiers: slot(exploitInput0.nullifier, padInput1.nullifier),
    inputCommitments: slot(exploitInput0.commitment, padInput1.commitment),
    inputValues: slot(exploitInput0.value, padInput1.value),
    inputSalts: slot(exploitInput0.salt, padInput1.salt),
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root: ZERO_ROOT,
    pathElements: slot(exploitInput0.path, padInput1.path),
    leafIndices: slot(exploitInput0.leafIndex, padInput1.leafIndex),
    enabled: slot(1n, 0n), // slot 7 enabled at a zero commitment => UNSATISFIABLE
    outputCommitments: outValues.map((v, i) => commitment(v, salt(i), owners[i])),
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    kemSs: kemDraw(label).kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

// --- withdraw (2-in / 1-out): out = sumInputs - sumOutputs = X ---------------------
function genWithdrawZeroLeaf(): WithdrawInput {
  const outValues = [0n]; // out = (X + 0) - 0 = X paid from nothing
  const owners: Point[] = [receiver(0).publicKey];
  const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));
  return {
    nullifiers: [exploitInput0.nullifier, padInput1.nullifier],
    inputCommitments: [exploitInput0.commitment, padInput1.commitment],
    inputValues: [exploitInput0.value, padInput1.value],
    inputSalts: [exploitInput0.salt, padInput1.salt],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    root: ZERO_ROOT,
    pathElements: [exploitInput0.path, padInput1.path],
    leafIndices: [exploitInput0.leafIndex, padInput1.leafIndex],
    enabled: [1n, 0n], // input0 enabled at a zero commitment => must be UNSATISFIABLE
    outputCommitments: outCommits,
    outputValues: outValues,
    outputSalts: outValues.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
    // §6b v2 authority envelope inputs (present + valid so witness-gen fails on
    // the zero-commitment belt, not on a missing input).
    ecdhPrivateKey: BigInt(ECDH_SK),
    kemSs: kemDraw("withdraw_zero_leaf").kemSs,
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
    recipient: 0x1111111111111111111111111111111111111111n,
  };
}

write("transfer_zero_leaf", genTransferZeroLeaf());
write("transfer10_zero_leaf", genSpend10ZeroLeaf("transfer10_zero_leaf", 10));
write("transfer10x2_zero_leaf", genSpend10ZeroLeaf("transfer10x2_zero_leaf", 2));
write("withdraw_zero_leaf", genWithdrawZeroLeaf());
console.log("zero-leaf exploit input generation OK");
