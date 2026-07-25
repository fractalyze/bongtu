// Disburse-256 oracle (M1 Done#1 / U5).
//
// Drives the U1 ImtTree reference at PRODUCTION arity (B=256, LOG_B=8, H=32)
// through the exact insert sequence the on-chain BongtuPool performs when the
// real GPU 256 disburse proof is spent against a pool seeded with the single
// input note:
//
//   appendLeaf(inputCommitment)   -> seedRoot  (must equal public.json[5],
//                                     the membership root the proof asserts)
//   attachSubtree(pub[3])         -> oracleRoot (root after the 256-subtree
//                                     attaches; the contract must match this)
//
// Proof calldata comes from disburse256.calldata.json — the output of
// `snarkjs groth16.exportSolidityCallData(disburse256.proof.json,
// disburse256.public.json)`, committed so snarkjs itself (not a hand-copied
// G2-swap rule) is the source of the verifier-call encoding; the Python
// prover_service/calldata.py is pinned against the same file
// (prover/tests/test_calldata.py). Regenerate it with that one snarkjs call if
// the proof fixture is ever re-proven.
//
// The spent input note is read from disburse256.input.json (the witness input
// the committed proof was generated from — NOT circuits/inputs/disburse256.json,
// whose local tree differs); override with BONGTU_DISBURSE256_INPUT. Emits
// disburse256.oracle.json for Disburse256.t.sol.
//
//   npx tsx gen_disburse256_oracle.ts   # writes disburse256.oracle.json

import { mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";

const HERE = dirname(fileURLToPath(import.meta.url));
const H = 32;
const B = 256;

// Real proof publics (10) — the rabbitsnark-GPU disburse256 proof.
const pub = JSON.parse(readFileSync(join(HERE, "disburse256.public.json"), "utf8"));
// Solidity-ready Groth16 calldata (snarkjs applied the G2 inner swap on b).
const cd = JSON.parse(readFileSync(join(HERE, "disburse256.calldata.json"), "utf8"));
// The input note that was spent (its commitment is the sole leaf of the
// membership tree the proof proves against).
const INPUT_PATH = process.env.BONGTU_DISBURSE256_INPUT ?? join(HERE, "disburse256.input.json");
const input = JSON.parse(readFileSync(INPUT_PATH, "utf8"));

const inputCommitment = BigInt(input.inputCommitments[0]);
const membershipRoot = BigInt(pub[5]); // proof's asserted root
const subtreeRoot = BigInt(pub[3]); // in-circuit 256-leaf subtree root
const nullifier = BigInt(pub[4]);
const arbiterKey = [BigInt(pub[8]), BigInt(pub[9])];

const s = (x: bigint | number | string): string => "0x" + BigInt(x).toString(16).padStart(64, "0");

// The calldata fixture must be the same proof run: its publics are the hex form
// of public.json, or the a/b/c we emit belong to a different proof.
if (JSON.stringify(cd.pub) !== JSON.stringify(pub.map(s))) {
  throw new Error("disburse256.calldata.json pub != disburse256.public.json — stale fixture?");
}

const tree = new ImtTree(H, B);

// 1. Seed the single input note as leaf 0. This MUST reproduce the proof's
//    membership root — the unification claim (SpendCycle pattern).
tree.appendLeaf(inputCommitment);
const seedRoot = tree.getRoot();
if (seedRoot !== membershipRoot) {
  throw new Error(
    `seedRoot != public.json[5]:\n  seedRoot=${seedRoot}\n  pub[5]  =${membershipRoot}`,
  );
}

// 2. Attach the 256-leaf disburse subtree (leaves unknown on-chain: the root is
//    computed from subtreeRoot alone, exactly as the contract does).
const nextLeafIndexBeforeAttach = tree.getNextLeafIndex();
tree.attachSubtree(subtreeRoot);
const oracleRoot = tree.getRoot();
const finalNextLeafIndex = tree.getNextLeafIndex();

const out = {
  height: H,
  batchSize: B,
  inputCommitment: s(inputCommitment),
  seedRoot: s(seedRoot), // == public.json[5]
  subtreeRoot: s(subtreeRoot), // == public.json[3]
  nullifier: s(nullifier), // == public.json[4]
  arbiterKey: arbiterKey.map(s), // == public.json[8..9]
  oracleRoot: s(oracleRoot), // root after appendLeaf + attachSubtree
  nextLeafIndexBeforeAttach, // 1
  finalNextLeafIndex, // pad(1->256) + attach(256) = 512
  // Real GPU proof in snarkjs exportSolidityCallData form + publics (hex).
  a: cd.a,
  b: cd.b,
  c: cd.c,
  pub: cd.pub,
};

mkdirSync(HERE, { recursive: true });
writeFileSync(join(HERE, "disburse256.oracle.json"), JSON.stringify(out, null, 2));
console.log("wrote disburse256.oracle.json");
console.log(`  seedRoot   = ${out.seedRoot}  (== public.json[5], verified)`);
console.log(`  oracleRoot = ${out.oracleRoot}`);
console.log(`  finalNextLeafIndex = ${finalNextLeafIndex} (expect 512)`);
