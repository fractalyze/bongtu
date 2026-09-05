// Consolidated CONSUMER real-proof fixture for the U4 module tests — the
// no-auditor sibling of gen_realproofs.ts (which owns the enterprise family
// and is NOT touched: the two files never share an entry).
//
// Reads circuits/out/<name>.{proof,public,vkey}.json for the five CPU consumer
// circuits (regenerate via circuits/build/prove_all.sh) plus the GPU-proven
// disbursePriv256 (CLAUDE.md GPU regen recipe), verifies every proof against
// its vkey, exports Solidity-ready calldata (snarkjs handles the pi_b G2
// swap), and — with the U1 ImtTree oracle — precomputes per circuit the seed
// leaves and the root AFTER the op advances the tree.
//
// Key-material notes (the consumer analogue of the enterprise file's
// kemCiphertext/kemBinding/arbiterKey trio): there is NO shared authority key
// in this family. What each entry carries instead, all re-derived from the
// SAME deterministic plan the witness inputs were generated from
// (circuits/fixtures/consumer_lib.ts, so agreement is structural):
//   kemCiphertexts   one 1088-byte ML-KEM-768 ct hex per output — the
//                    module's `bytes[] kemCiphertexts` calldata (OPMOD §3.4);
//   disclosure       (disburse fixtures) the 6B-element module calldata array
//                    receiverCts[4B] ++ viewTags[B] ++ outputCommitments[B],
//                    belt-checked to fold to the proof's disclosureHash
//                    (OPMOD §4.1/§4.2);
//   kemChunks[K] + kemChunkHashes[K] + chunkArity
//                    (disbursePriv256) the OPMOD §5 Option A-chunked kem-ct
//                    transport: chunk j = outputs [86j..) in leaf order,
//                    keccak-bound to the batch tx.
// Every ct/viewTag/commitment PUBLIC is additionally belt-checked against the
// re-derived seals, the same role gen_realproofs.ts's kemBinding cross-check
// plays.
//
//   npx tsx gen_consumer_realproofs.ts   # writes consumer_realproofs.json

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { keccak256 } from "viem";

import { consumerDisclosureElements } from "@bongtu/core/consumer";
import { disclosureChain } from "@bongtu/core/envelope";
import { loadSnarkjs } from "@bongtu/core/extern";
import { ImtTree } from "@bongtu/core/imt";

import {
  DISBURSE_PRIV256_B,
  DISBURSE_PRIV_B,
  depositPrivPlan,
  disbursePriv256Plan,
  disbursePrivPlan,
  sealPlan,
  transfer10x2PrivPlan,
  transferPrivPlan,
  withdrawPrivPlan,
} from "../../../../circuits/fixtures/consumer_lib.js";
import type { SealedPlanOutput } from "../../../../circuits/fixtures/consumer_lib.js";

// snarkjs comes back `any` from the shared external loader (@bongtu/core/extern).
const snarkjs = loadSnarkjs();

const HERE = dirname(fileURLToPath(import.meta.url));
const CIRC = join(HERE, "..", "..", "..", "..", "circuits");
const OUT = join(CIRC, "out");
const INPUTS = join(CIRC, "fixtures", "inputs");
const H = 32;

// OPMOD §5 Option A-chunked: kem cts ride in K = ceil(256/86) = 3 chunk txs.
const CHUNK_ARITY = 86;

// Filler leaf padding the 1-membership-leaf disbursePriv up to the 2-leaf
// deposit seed the tests use (same rationale as gen_realproofs.ts FILLER).
const FILLER = 1n;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const rd = (p: string): any => JSON.parse(readFileSync(p, "utf8"));
const s = (x: bigint | number | string): string => "0x" + BigInt(x).toString(16).padStart(64, "0");
const hex = (b: Uint8Array): string => "0x" + Buffer.from(b).toString("hex");

function assertEq(got: bigint | number | string, want: bigint | number | string, msg: string): void {
  if (BigInt(got) !== BigInt(want)) throw new Error(`${msg}: got ${got} want ${want}`);
}

// exportSolidityCallData + a groth16.verify belt: a stale out/ (proof not from
// the current circuit/vkey build) fails HERE, not in a forge test later.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function calldata(name: string): Promise<{ a: any; b: any; c: any; pub: string[] }> {
  const proof = rd(join(OUT, `${name}.proof.json`));
  const pub = rd(join(OUT, `${name}.public.json`));
  const vkey = rd(join(OUT, `${name}.vkey.json`));
  if (!(await snarkjs.groth16.verify(vkey, pub, proof))) {
    throw new Error(`${name}: committed proof does not verify against out/${name}.vkey.json (stale out/?)`);
  }
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, pub);
  const [a, b, c, signals] = JSON.parse("[" + cd + "]");
  return { a, b, c, pub: signals };
}

function rootAfterAppends(commitments: (bigint | number | string)[], batch = 16): bigint {
  const t = new ImtTree(H, batch);
  for (const c of commitments) t.appendLeaf(BigInt(c));
  return t.getRoot();
}

/** Belt: the proof's ct / viewTag / outputCommitment publics equal the seals
 *  re-derived from the shared plan — the consumer analogue of the enterprise
 *  kemBinding cross-check. `at` gives each run's start index in the layout. */
function assertSealsMatch(
  label: string,
  pub: string[],
  at: { cts: number; tags: number; oc: number },
  sealed: SealedPlanOutput[],
): void {
  for (const [i, o] of sealed.entries()) {
    for (const [j, cj] of o.seal.cipherText.entries()) {
      assertEq(pub[at.cts + 4 * i + j], cj, `${label} ct[${i}][${j}] public != seal`);
    }
    assertEq(pub[at.tags + i], o.seal.viewTag, `${label} viewTag[${i}] public != seal`);
    assertEq(pub[at.oc + i], o.commitment, `${label} outputCommitment[${i}] public != plan`);
  }
}

const kemHexes = (sealed: SealedPlanOutput[]): string[] => sealed.map((o) => hex(o.seal.kemCiphertext));

const disclosureOf = (sealed: SealedPlanOutput[]): bigint[] =>
  consumerDisclosureElements(
    sealed.map((o) => o.seal.cipherText),
    sealed.map((o) => o.seal.viewTag),
    sealed.map((o) => o.commitment),
  );

async function main(): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const out: Record<string, any> = {};

  // --- depositPriv (0-in / 2-out mint) -------------------------------------
  // publics (16): [0]=out [1..2]=ecdhPub [3..10]=cipherTexts[2][4]
  //               [11..12]=viewTags [13..14]=oc [15]=nonce
  {
    const cd = await calldata("depositPriv");
    const sealed = sealPlan("depositPriv", depositPrivPlan());
    assertSealsMatch("depositPriv", cd.pub, { cts: 3, tags: 11, oc: 13 }, sealed);
    const t = new ImtTree(H, 16);
    t.appendLeaf(BigInt(cd.pub[13]));
    t.appendLeaf(BigInt(cd.pub[14]));
    out.depositPriv = { ...cd, rootAfter: s(t.getRoot()), kemCiphertexts: kemHexes(sealed) };
  }

  // --- transferPriv (2-in / 2-out) -----------------------------------------
  // publics (20): [0..1]=ecdhPub [2..9]=cts [10..11]=viewTags [12..13]=nf
  //               [14]=root [15..16]=enabled [17..18]=oc [19]=nonce
  {
    const cd = await calldata("transferPriv");
    const sealed = sealPlan("transferPriv", transferPrivPlan());
    assertSealsMatch("transferPriv", cd.pub, { cts: 2, tags: 10, oc: 17 }, sealed);
    const inC = rd(join(INPUTS, "transferPriv.json")).inputCommitments as string[];
    assertEq(rootAfterAppends(inC), cd.pub[14], "transferPriv membership root != pub[14]");
    const t = new ImtTree(H, 16);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[17]));
    t.appendLeaf(BigInt(cd.pub[18]));
    out.transferPriv = {
      ...cd,
      seedLeaves: inC.map(s),
      rootAfter: s(t.getRoot()),
      kemCiphertexts: kemHexes(sealed),
    };
  }

  // --- transfer10x2Priv (10-in / 2-out, 4 real + 6 padded inputs) ----------
  // publics (36): [0..1]=ecdhPub [2..9]=cts [10..11]=viewTags [12..21]=nf
  //               [22]=root [23..32]=enabled [33..34]=oc [35]=nonce
  {
    const cd = await calldata("transfer10x2Priv");
    const sealed = sealPlan("transfer10x2Priv", transfer10x2PrivPlan());
    assertSealsMatch("transfer10x2Priv", cd.pub, { cts: 2, tags: 10, oc: 33 }, sealed);
    const inp = rd(join(INPUTS, "transfer10x2Priv.json"));
    const seed = (inp.inputCommitments as string[])
      .filter((_, i) => BigInt(inp.enabled[i]) === 1n)
      .map(BigInt);
    assertEq(rootAfterAppends(seed), cd.pub[22], "transfer10x2Priv membership root != pub[22]");
    const t = new ImtTree(H, 16);
    for (const c of seed) t.appendLeaf(c);
    t.appendLeaf(BigInt(cd.pub[33]));
    t.appendLeaf(BigInt(cd.pub[34]));
    out.transfer10x2Priv = {
      ...cd,
      seedLeaves: seed.map(s),
      rootAfter: s(t.getRoot()),
      kemCiphertexts: kemHexes(sealed),
    };
  }

  // --- withdrawPriv (2-in / 1-out change + proof-bound recipient) ----------
  // publics (16): [0]=out [1..2]=ecdhPub [3..6]=ctChange [7]=viewTag
  //               [8..9]=nf [10]=root [11..12]=enabled [13]=oc0(change)
  //               [14]=nonce [15]=recipient
  {
    const cd = await calldata("withdrawPriv");
    const sealed = sealPlan("withdrawPriv", withdrawPrivPlan());
    assertSealsMatch("withdrawPriv", cd.pub, { cts: 3, tags: 7, oc: 13 }, sealed);
    const inC = rd(join(INPUTS, "withdrawPriv.json")).inputCommitments as string[];
    assertEq(rootAfterAppends(inC), cd.pub[10], "withdrawPriv membership root != pub[10]");
    const t = new ImtTree(H, 16);
    for (const c of inC) t.appendLeaf(BigInt(c));
    t.appendLeaf(BigInt(cd.pub[13]));
    out.withdrawPriv = {
      ...cd,
      seedLeaves: inC.map(s),
      rootAfter: s(t.getRoot()),
      kemCiphertexts: kemHexes(sealed),
    };
  }

  // --- disbursePriv (1-in / 16-out dev-loop batch) -------------------------
  // publics (8): [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot [4]=nf
  //              [5]=root [6]=enabled [7]=nonce
  // Seed = 2-leaf deposit [inCommit, FILLER] (the 1-leaf membership root is
  // known after the first seeded append), then the depth-4 subtree attaches.
  {
    const cd = await calldata("disbursePriv");
    const sealed = sealPlan("disbursePriv", disbursePrivPlan());
    const disclosure = disclosureOf(sealed);
    assertEq(disclosureChain(disclosure), cd.pub[2], "disbursePriv fold(disclosure) != pub[2]");
    if (disclosure.length !== 6 * DISBURSE_PRIV_B) {
      throw new Error(`disbursePriv disclosure is ${disclosure.length} elements, want ${6 * DISBURSE_PRIV_B}`);
    }
    const inCommit = rd(join(INPUTS, "disbursePriv.json")).inputCommitments[0] as string;
    assertEq(rootAfterAppends([inCommit]), cd.pub[5], "disbursePriv membership root != pub[5]");
    const seed = [BigInt(inCommit), FILLER];
    const t = new ImtTree(H, 16);
    for (const c of seed) t.appendLeaf(c);
    t.attachSubtree(BigInt(cd.pub[3]));
    out.disbursePriv = {
      ...cd,
      seedLeaves: seed.map(s),
      rootAfter: s(t.getRoot()),
      disclosure: disclosure.map(s),
      kemCiphertexts: kemHexes(sealed),
    };
  }

  // --- disbursePriv256 (1-in / 256-out production batch, GPU-proven) -------
  // Same publics (8). Single-leaf seed (the gen_disburse256_oracle pattern);
  // kem cts ride as K=3 keccak-bound chunks, not batch-tx calldata (OPMOD §5).
  {
    const cd = await calldata("disbursePriv256");
    const sealed = sealPlan("disbursePriv256", disbursePriv256Plan());
    const disclosure = disclosureOf(sealed);
    assertEq(disclosureChain(disclosure), cd.pub[2], "disbursePriv256 fold(disclosure) != pub[2]");
    if (disclosure.length !== 6 * DISBURSE_PRIV256_B) {
      throw new Error(
        `disbursePriv256 disclosure is ${disclosure.length} elements, want ${6 * DISBURSE_PRIV256_B}`,
      );
    }
    const inCommit = rd(join(INPUTS, "disbursePriv256.json")).inputCommitments[0] as string;
    assertEq(rootAfterAppends([inCommit], 256), cd.pub[5], "disbursePriv256 membership root != pub[5]");
    const t = new ImtTree(H, 256);
    t.appendLeaf(BigInt(inCommit));
    t.attachSubtree(BigInt(cd.pub[3]));
    const chunkCount = Math.ceil(DISBURSE_PRIV256_B / CHUNK_ARITY);
    const chunks = Array.from({ length: chunkCount }, (_, j) =>
      Buffer.concat(
        sealed
          .slice(j * CHUNK_ARITY, Math.min((j + 1) * CHUNK_ARITY, DISBURSE_PRIV256_B))
          .map((o) => Buffer.from(o.seal.kemCiphertext)),
      ),
    );
    out.disbursePriv256 = {
      ...cd,
      seedLeaves: [BigInt(inCommit)].map(s),
      rootAfter: s(t.getRoot()),
      disclosure: disclosure.map(s),
      chunkArity: CHUNK_ARITY,
      kemChunks: chunks.map((b) => "0x" + b.toString("hex")),
      kemChunkHashes: chunks.map((b) => keccak256(new Uint8Array(b))),
    };
  }

  writeFileSync(join(HERE, "consumer_realproofs.json"), JSON.stringify(out, null, 2));
  console.log("wrote consumer_realproofs.json (all belt-checks passed)");
}

main()
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
