// Consolidated real-proof fixture for the U3 soundness/accept tests.
//
// Reads the committed circuits/out/<name>.{proof,public}.json (regenerate via
// circuits/prove_all.sh + gen_attack_inputs.ts if out/ is gone), exports
// Solidity-ready calldata (snarkjs handles the pi_b G2 swap), and — using the
// U1 ImtTree oracle — precomputes, per circuit, the input commitments the
// contract must append to reproduce the proof's membership root and the oracle
// root AFTER the op advances the tree. The tests read this one JSON so the
// forge run needs no snarkjs.
//
//   npx tsx gen_realproofs.ts   # writes realproofs.json

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { ImtTree } from "@bongtu/sdk/imt";

const require = createRequire(import.meta.url);
// Single toolchain-node_modules constant (see docs/toolchain.md `SNARKJS`/`CIRCOMLIB`);
// override with BONGTU_NODE_MODULES. Default = the verified docs/toolchain.md path.
const NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";
// snarkjs ships no usable types here and is loaded via createRequire, so it is `any`.
const snarkjs = require(join(NODE_MODULES, "snarkjs/build/main.cjs"));

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRC = join(HERE, "..", "..", "..", "circuits");
const OUT = join(CIRC, "out");
const INPUTS = join(CIRC, "inputs");
const H = 32;
const B = 16;

const rd = (p: string): any => JSON.parse(readFileSync(p, "utf8"));
const s = (x: bigint | number | string): string => "0x" + BigInt(x).toString(16).padStart(64, "0");

async function calldata(name: string) {
  const proof = rd(join(OUT, `${name}.proof.json`));
  const pub = rd(join(OUT, `${name}.public.json`));
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, pub);
  const [a, b, c, signals] = JSON.parse("[" + cd + "]");
  return { a, b, c, pub: signals };
}

// append `commitments` as single leaves into a fresh tree, return the root
function rootAfterAppends(commitments: (bigint | number | string)[]): bigint {
  const t = new ImtTree(H, B);
  for (const c of commitments) t.appendLeaf(BigInt(c));
  return t.getRoot();
}

// Filler leaf used to pad a 1-membership-leaf circuit (disburse) up to the
// 2-leaf `deposit` seed the tests use. Any nonzero field element works; the
// disburse membership root (a 1-leaf tree) is marked known after the FIRST
// seeded append regardless of the filler.
const FILLER = 1n;

function assertEq(got: bigint | number | string, want: bigint | number | string, msg: string): void {
  if (BigInt(got) !== BigInt(want)) throw new Error(`${msg}: got ${got} want ${want}`);
}

async function main(): Promise<void> {
  const out: Record<string, any> = {};

  // --- deposit (mint, no membership) ---------------------------------------
  // deposit publics (18): [0]=out [1..2]=ecdhPub [3..12]=cipherTextAuthority[10]
  //                       [13..14]=oc [15]=nonce [16..17]=authorityPubKey
  {
    const cd = await calldata("deposit");
    const t = new ImtTree(H, B);
    t.appendLeaf(BigInt(cd.pub[13]));
    t.appendLeaf(BigInt(cd.pub[14]));
    out.deposit = { ...cd, rootAfter: s(t.getRoot()) };
  }

  // --- disburse (1-in / 16-out) --------------------------------------------
  // Seed = 2-leaf deposit [inCommit, FILLER]; the 1-leaf disburse membership
  // root (pub[5]) is marked known after the first seeded append. The op then
  // pads 2->16 and attaches the subtree.
  {
    const cd = await calldata("disburse");
    const inCommit = rd(join(INPUTS, "disburse.json")).inputCommitments[0];
    assertEq(rootAfterAppends([inCommit]), cd.pub[5], "disburse membership root != pub[5]");
    const seed = [BigInt(inCommit), FILLER];
    const t = new ImtTree(H, B);
    for (const c of seed) t.appendLeaf(c);
    t.attachSubtree(BigInt(cd.pub[3])); // subtreeRoot
    out.disburse = { ...cd, seedLeaves: seed.map(s), rootAfter: s(t.getRoot()) };
  }

  // --- transfer (2-in / 2-out) ---------------------------------------------
  // Seed = 2-leaf deposit of the two input commitments == transfer membership
  // tree (pub[28]); op appends the 2 output commitments.
  {
    const cd = await calldata("transfer");
    const inC = rd(join(INPUTS, "transfer.json")).inputCommitments;
    assertEq(rootAfterAppends(inC), cd.pub[28], "transfer membership root != pub[28]");
    const t = new ImtTree(H, B);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[31]));
    t.appendLeaf(BigInt(cd.pub[32]));
    out.transfer = { ...cd, seedLeaves: inC.map(s), rootAfter: s(t.getRoot()) };
  }

  // --- withdraw (2-in / 1-out) ---------------------------------------------
  // withdraw publics (25): [0]=out [1..2]=ecdhPub [3..15]=cipherTextAuthority[13]
  //   [16..17]=nf [18]=root [19..20]=enabled [21]=oc0(change) [22]=nonce
  //   [23..24]=authorityPubKey
  {
    const cd = await calldata("withdraw");
    const inC = rd(join(INPUTS, "withdraw.json")).inputCommitments;
    assertEq(rootAfterAppends(inC), cd.pub[18], "withdraw membership root != pub[18]");
    const t = new ImtTree(H, B);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[21]));
    out.withdraw = { ...cd, seedLeaves: inC.map(s), rootAfter: s(t.getRoot()) };
  }

  // NOTE: withdraw_attack (enabled=0 on a value-carrying input) and the pure
  // mint-from-nothing (nullifier=0/value!=0/enabled=0) are NO LONGER provable —
  // the circuit value-belt `(1-enabled[i])*inputValues[i]===0` makes their
  // witnesses unsatisfiable (see circuits/assert_attacks_throw.ts). There is
  // therefore no attack proof/calldata to emit; the vector is closed one layer
  // deeper than the old contract-injection defense.

  // --- withdraw_padded (nullifier=0,enabled=0 padded slot => must ACCEPT) ----
  {
    const cd = await calldata("withdraw_padded");
    const inC = rd(join(INPUTS, "withdraw_padded.json")).inputCommitments;
    assertEq(rootAfterAppends(inC), cd.pub[18], "padded membership root != pub[18]");
    const t = new ImtTree(H, B);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[21]));
    out.withdraw_padded = { ...cd, seedLeaves: inC.map(s), rootAfter: s(t.getRoot()) };
  }

  // --- arbiter key (authority pubkey the real proofs encrypt to) ------------
  // Every circuit's authority envelope must encrypt to the SAME key, since the
  // contract injects one stored arbiter key for ALL verifier calls (a proof made
  // for a different key FAILS after injection). disburse pub[8..9] == transfer
  // pub[34..35] == deposit pub[16..17] == withdraw pub[23..24] == AUTHORITY.publicKey.
  out.arbiterKey = [s(out.disburse.pub[8]), s(out.disburse.pub[9])];
  assertEq(out.transfer.pub[34], out.arbiterKey[0], "transfer authX != disburse authX");
  assertEq(out.transfer.pub[35], out.arbiterKey[1], "transfer authY != disburse authY");
  assertEq(out.deposit.pub[16], out.arbiterKey[0], "deposit authX != disburse authX");
  assertEq(out.deposit.pub[17], out.arbiterKey[1], "deposit authY != disburse authY");
  assertEq(out.withdraw.pub[23], out.arbiterKey[0], "withdraw authX != disburse authX");
  assertEq(out.withdraw.pub[24], out.arbiterKey[1], "withdraw authY != disburse authY");

  mkdirSync(HERE, { recursive: true });
  writeFileSync(join(HERE, "realproofs.json"), JSON.stringify(out, null, 2));
  console.log("wrote realproofs.json (all membership-root self-checks passed)");
  console.log("  arbiterKey =", out.arbiterKey);
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
