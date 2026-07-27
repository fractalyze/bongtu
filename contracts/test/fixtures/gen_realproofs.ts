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

import { ImtTree } from "@bongtu/core/imt";
import { kemBindingOf } from "@bongtu/core/kem";
import { loadSnarkjs } from "@bongtu/core/extern";
// The fixture KEM material (deterministic keypair + per-fixture encapsulation)
// is owned by the circuits fixture preamble — same-source as the inputs the
// proofs were generated from, so ct/limbs/binding stay consistent by construction.
import { AUTHORITY_KEM, kemDraw } from "../../../circuits/fixture_lib.js";

// snarkjs comes back `any` from the shared external loader (@bongtu/core/extern).
const snarkjs = loadSnarkjs();

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRC = join(HERE, "..", "..", "..", "circuits");
const OUT = join(CIRC, "out");
const INPUTS = join(CIRC, "inputs");
const H = 32;
const B = 16;

const rd = (p: string): any => JSON.parse(readFileSync(p, "utf8"));
const s = (x: bigint | number | string): string => "0x" + BigInt(x).toString(16).padStart(64, "0");
const hex = (b: Uint8Array): string => "0x" + Buffer.from(b).toString("hex");

// PQ envelope (pq-envelope-design.md §3): re-derive the fixture KEM draw for a
// proof, belt-check its binding against the proof's own kemBinding public, and
// return what U-P2's contract tests need (the 1088-byte ct + the binding).
function kemFor(label: string, kemBindingPub: bigint | number | string): { kemCiphertext: string; kemBinding: string } {
  const draw = kemDraw(label);
  assertEq(kemBindingOf(draw.kemSs), kemBindingPub, `${label} kemBinding public != binding(fixture kemSs)`);
  return { kemCiphertext: hex(draw.kemCiphertext), kemBinding: BigInt(kemBindingPub).toString() };
}

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
  // deposit publics (19): [0]=out [1..2]=ecdhPub [3..12]=cipherTextAuthority[10]
  //                       [13]=kemBinding [14..15]=oc [16]=nonce [17..18]=authorityPubKey
  {
    const cd = await calldata("deposit");
    const t = new ImtTree(H, B);
    t.appendLeaf(BigInt(cd.pub[14]));
    t.appendLeaf(BigInt(cd.pub[15]));
    out.deposit = { ...cd, rootAfter: s(t.getRoot()), ...kemFor("deposit", cd.pub[13]) };
  }

  // --- disburse (1-in / 16-out) --------------------------------------------
  // Seed = 2-leaf deposit [inCommit, FILLER]; the 1-leaf disburse membership
  // root (pub[5]) is marked known after the first seeded append. The op then
  // pads 2->16 and attaches the subtree.
  {
    const cd = await calldata("disburse");
    const inCommit = rd(join(INPUTS, "disburse.json")).inputCommitments[0];
    assertEq(rootAfterAppends([inCommit]), cd.pub[6], "disburse membership root != pub[6]");
    const seed = [BigInt(inCommit), FILLER];
    const t = new ImtTree(H, B);
    for (const c of seed) t.appendLeaf(c);
    t.attachSubtree(BigInt(cd.pub[3])); // subtreeRoot
    out.disburse = { ...cd, seedLeaves: seed.map(s), rootAfter: s(t.getRoot()), ...kemFor("disburse", cd.pub[4]) };
  }

  // --- transfer (2-in / 2-out) ---------------------------------------------
  // Seed = 2-leaf deposit of the two input commitments == transfer membership
  // tree (pub[28]); op appends the 2 output commitments.
  {
    const cd = await calldata("transfer");
    const inC = rd(join(INPUTS, "transfer.json")).inputCommitments;
    assertEq(rootAfterAppends(inC), cd.pub[29], "transfer membership root != pub[29]");
    const t = new ImtTree(H, B);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[32]));
    t.appendLeaf(BigInt(cd.pub[33]));
    out.transfer = { ...cd, seedLeaves: inC.map(s), rootAfter: s(t.getRoot()), ...kemFor("transfer", cd.pub[26]) };
  }

  // --- withdraw (2-in / 1-out) ---------------------------------------------
  // withdraw publics (26): [0]=out [1..2]=ecdhPub [3..15]=cipherTextAuthority[13]
  //   [16]=kemBinding [17..18]=nf [19]=root [20..21]=enabled [22]=oc0(change)
  //   [23]=nonce [24..25]=authorityPubKey
  {
    const cd = await calldata("withdraw");
    const inC = rd(join(INPUTS, "withdraw.json")).inputCommitments;
    assertEq(rootAfterAppends(inC), cd.pub[19], "withdraw membership root != pub[19]");
    const t = new ImtTree(H, B);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[22]));
    out.withdraw = { ...cd, seedLeaves: inC.map(s), rootAfter: s(t.getRoot()), ...kemFor("withdraw", cd.pub[16]) };
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
    assertEq(rootAfterAppends(inC), cd.pub[19], "padded membership root != pub[19]");
    const t = new ImtTree(H, B);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[22]));
    out.withdraw_padded = { ...cd, seedLeaves: inC.map(s), rootAfter: s(t.getRoot()), ...kemFor("withdraw_padded", cd.pub[16]) };
  }

  // --- arbiter key (authority pubkey the real proofs encrypt to) ------------
  // Every circuit's authority envelope must encrypt to the SAME key, since the
  // contract injects one stored arbiter key for ALL verifier calls (a proof made
  // for a different key FAILS after injection). disburse pub[9..10] == transfer
  // pub[35..36] == deposit pub[17..18] == withdraw pub[24..25] == AUTHORITY.publicKey.
  out.arbiterKey = [s(out.disburse.pub[9]), s(out.disburse.pub[10])];
  assertEq(out.transfer.pub[35], out.arbiterKey[0], "transfer authX != disburse authX");
  assertEq(out.transfer.pub[36], out.arbiterKey[1], "transfer authY != disburse authY");
  assertEq(out.deposit.pub[17], out.arbiterKey[0], "deposit authX != disburse authX");
  assertEq(out.deposit.pub[18], out.arbiterKey[1], "deposit authY != disburse authY");
  assertEq(out.withdraw.pub[24], out.arbiterKey[0], "withdraw authX != disburse authX");
  assertEq(out.withdraw.pub[25], out.arbiterKey[1], "withdraw authY != disburse authY");

  // --- arbiter ML-KEM-768 encapsulation key (PQ half of the hybrid envelope) --
  // Joins the fixture metadata the same way arbiterKey does: every fixture
  // proof's kemBinding is bound to a ct encapsulated to THIS key (belt-checked
  // per-op in kemFor above). U-P2 pins keccak256 of these bytes on-chain.
  out.kemPublicKey = hex(AUTHORITY_KEM.publicKey);

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
