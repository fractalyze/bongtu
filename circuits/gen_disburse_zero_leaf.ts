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

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/sdk/imt";
import { deriveKeypair, commitment, nullifier } from "@bongtu/sdk/note";
import type { Keypair } from "@bongtu/sdk/note";
import type { Point } from "@bongtu/sdk/babyjub";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "inputs");
const H = 32;

const SENDER = deriveKeypair(
  2736030358979909402780800718157159386076813972158567259200215660948447373041n - 12345n,
);
const ECDH_SK = 987654321987654321987654321n;
const AUTHORITY = deriveKeypair(555555555555555555555555n);
const receiver = (i: number): Keypair => deriveKeypair(1000000007n + BigInt(i) * 1000003n);
const salt = (i: number): bigint => 1000000n + BigInt(i);
const ENCRYPTION_NONCE = 424242424242n;
const X = 1000000000000n; // 1e12, arbitrary value never deposited

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

const emptyTree = new ImtTree(H, 16);
const ZERO_ROOT = emptyTree.getRoot();
const ZERO_PATH = emptyTree.zeros.slice(0, H);

// disburse (Zeto(1,16,32)): single enabled input at a zero commitment.
const N = 16;
// outputs sum to X so CheckSum (equality) passes; only the belt is unsatisfiable.
const outValues = [X, ...Array.from({ length: N - 1 }, () => 0n)];
const owners: Point[] = Array.from({ length: N }, (_, i) => receiver(i).publicKey);
const outCommits = outValues.map((v, i) => commitment(v, salt(i), owners[i]));

const obj = {
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

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(join(OUT_DIR, "disburse_zero_leaf.json"), JSON.stringify(jsonify(obj), null, 2));
console.log("  wrote inputs/disburse_zero_leaf.json");
