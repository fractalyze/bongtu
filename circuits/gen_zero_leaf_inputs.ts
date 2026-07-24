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
// assertion string then names the spending base template. Run through tsx:
//
//   npx tsx gen_zero_leaf_inputs.ts   # writes inputs/{transfer,withdraw}_zero_leaf.json

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "../sdk/src/imt.js";
import { deriveKeypair, commitment, nullifier } from "../sdk/src/note.js";
import type { Keypair } from "../sdk/src/note.js";
import type { Point } from "../sdk/src/babyjub.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "inputs");
const H = 32; // IMT depth (all circuits)

// Same test material as gen_inputs.ts so these stay consistent with the honest fixtures.
const SENDER = deriveKeypair(
  2736030358979909402780800718157159386076813972158567259200215660948447373041n - 12345n,
);
const ECDH_SK = 987654321987654321987654321n;
const AUTHORITY = deriveKeypair(555555555555555555555555n);
const receiver = (i: number): Keypair => deriveKeypair(1000000007n + BigInt(i) * 1000003n);
const salt = (i: number): bigint => 1000000n + BigInt(i);
const ENCRYPTION_NONCE = 424242424242n;

// The arbitrary value the attacker mints from a padded 0-leaf they never deposited.
// Well within the stock 100-bit range so CheckPositive/GreaterEqThan witness-gen
// succeeds and the ONLY unsatisfiable constraint is the new zero-commitment belt.
const X = 1000000000000n; // 1e12

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

// A genuine membership proof of the 0-leaf at index 0 of an EMPTY tree:
// root = zeros[H], siblings = zeros[0..H-1]. Folding leaf 0 up with these zeros
// siblings reproduces zeros[H] exactly, so CheckIMTProof holds at enabled=1.
const emptyTree = new ImtTree(H, 16);
const ZERO_ROOT = emptyTree.getRoot(); // == zeros[H]
const ZERO_PATH = emptyTree.zeros.slice(0, H); // zeros[0..H-1], length H

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
function genTransferZeroLeaf() {
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
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

// --- withdraw (2-in / 1-out): out = sumInputs - sumOutputs = X ---------------------
function genWithdrawZeroLeaf() {
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
    encryptionNonce: ENCRYPTION_NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };
}

write("transfer_zero_leaf", genTransferZeroLeaf());
write("withdraw_zero_leaf", genWithdrawZeroLeaf());
console.log("zero-leaf exploit input generation OK");
