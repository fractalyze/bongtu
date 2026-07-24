// Deterministic witness-input generator for the 4 bongtu M0 circuits.
//
// Builds each circuit's input.json from the U1 SDK: real ImtTree membership
// witnesses (root + pathElements + leafIndices), poseidon commitments /
// nullifiers, and the two-time-pad dup-owner guard. No Math.random — every
// scalar / salt / nonce is derived from an index, so fixtures are reproducible.
//
//   npx tsx gen_inputs.ts        # writes inputs/{deposit,disburse,transfer,withdraw}.json
//
// The tree the input notes are inserted into is the SAME single-frontier IMT the
// contract (U3) and e2e (U4) use, so the membership witnesses stay consistent.

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "../sdk/src/imt.js";
import {
  deriveKeypair,
  commitment,
  nullifier,
  assertDistinctOwnerPubkeys,
} from "../sdk/src/note.js";
import type { Keypair } from "../sdk/src/note.js";
import type { Point } from "../sdk/src/babyjub.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "inputs");
const H = 32; // IMT depth (all circuits)

// --- fixed test material (index-derived, PRNG-free) ------------------------

// The sender owns every spent input note (the base uses one inputOwnerPrivateKey).
const SENDER = deriveKeypair(
  2736030358979909402780800718157159386076813972158567259200215660948447373041n - 12345n,
);
// Ephemeral ECDH key for output/authority encryption, and the authority key.
const ECDH_SK = 987654321987654321987654321n;
const AUTHORITY = deriveKeypair(555555555555555555555555n);

// Distinct receiver keypair per output index (distinct scalars => distinct pubkeys).
function receiver(i: number): Keypair {
  return deriveKeypair(1000000007n + BigInt(i) * 1000003n);
}
const salt = (i: number): bigint => 1000000n + BigInt(i);
const ENCRYPTION_NONCE = 424242424242n; // < 2^128

// Recursively stringify BigInt for snarkjs JSON.
function jsonify(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(jsonify);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) o[k] = jsonify((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

function write(name: string, obj: unknown): void {
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, `${name}.json`), JSON.stringify(jsonify(obj), null, 2));
  console.log(`  wrote inputs/${name}.json`);
}

interface Membership {
  root: bigint;
  pathElements: bigint[][];
  leafIndices: bigint[];
}

// Insert `commitments` as single leaves into a fresh tree and return the root +
// per-leaf { leafIndices, pathElements } membership witness (index-keyed IMT).
function membership(commitments: bigint[]): Membership {
  const tree = new ImtTree(H, 16);
  const indices = commitments.map((c) => {
    const idx = tree.getNextLeafIndex();
    tree.appendLeaf(c);
    return idx;
  });
  const root = tree.getRoot();
  const pathElements: bigint[][] = [];
  const leafIndices: bigint[] = [];
  for (const idx of indices) {
    const { siblings } = tree.merklePath(idx);
    pathElements.push(siblings);
    leafIndices.push(BigInt(idx));
  }
  return { root, pathElements, leafIndices };
}

// --- deposit (0-in / 2-out), stock Deposit(2) ------------------------------

function genDeposit() {
  const values = [1000n, 2000n];
  const owners: Point[] = values.map((_, i) => receiver(i).publicKey);
  assertDistinctOwnerPubkeys(owners);
  const outputCommitments = values.map((v, i) => commitment(v, salt(i), owners[i]));
  return {
    outputCommitments,
    outputValues: values,
    outputSalts: values.map((_, i) => salt(i)),
    outputOwnerPublicKeys: owners,
  };
}

// --- disburse (1-in / 16-out), Zeto(1,16,32) -------------------------------

function genDisburse() {
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

function genTransfer() {
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

function genWithdraw() {
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
  };
}

write("deposit", genDeposit());
write("disburse", genDisburse());
write("transfer", genTransfer());
write("withdraw", genWithdraw());
console.log("input generation OK");
