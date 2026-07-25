// Deterministic witness-input generator for the PRODUCTION 1×256 disburse circuit.
//
// Writes inputs/disburse256.json — a complete, satisfying circom input for
// circuits/out/disburse256_js — used as the prover service's boot warm-up proof
// (prover/README.md) and as the repo-native fixture for exercising the service
// end-to-end. gen_inputs.ts covers the M0 1×16 dev build; this covers the 1×256.
//
// Same conventions as gen_inputs.ts: PRNG-free (every scalar is index-derived),
// real ImtTree membership, the §11-8 distinct-owner guard. The key material
// mirrors deploy/giwa_disburse256.ts (employer / recipient / ECDH seeds) so the
// fixture stays faithful to the live runner, but the tree here is local (leaf 0
// a dummy note, leaf 1 the spent input note) — the proof verifies against the
// disburse256 vkey with its own self-consistent root, no chain state involved.
//
//   npx tsx gen_disburse256_input.ts     # writes inputs/disburse256.json

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/sdk/imt";
import {
  deriveKeypair,
  commitment,
  nullifier,
  assertDistinctOwnerPubkeys,
} from "@bongtu/sdk/note";
import type { Keypair } from "@bongtu/sdk/note";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "inputs");
const H = 32; // IMT depth
const B = 256; // production disburse batch size

// deploy/giwa_disburse256.ts key material (deterministic, PRNG-free).
const EMPLOYER = deriveKeypair(313131313131313131313131n);
const recipient = (i: number): Keypair => deriveKeypair(4000000019n + BigInt(i) * 1000003n);
const ECDH = 900000000000000000007n;
const NONCE = 424242424243n;
const AUTHORITY = deriveKeypair(555555555555555555555555n); // gen_inputs.ts authority
const inSalt = 8000001n;
const outSalt = (i: number): bigint => 9000000n + BigInt(i);

// Recursively stringify BigInt for witness-calculator JSON.
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

function main(): void {
  const amounts = Array.from({ length: B }, (_, i) => 100n + BigInt(i)); // 256 distinct positive
  const V = amounts.reduce((a, x) => a + x, 0n);

  // A tiny local tree: leaf 0 a dummy note, leaf 1 = the input note we spend.
  const tree = new ImtTree(H, B);
  tree.appendLeaf(commitment(1n, 1n, EMPLOYER.publicKey));
  const inCommit = commitment(V, inSalt, EMPLOYER.publicKey);
  const leafIndex = tree.getNextLeafIndex();
  tree.appendLeaf(inCommit);
  const { siblings } = tree.merklePath(leafIndex);

  const owners = Array.from({ length: B }, (_, i) => recipient(i).publicKey);
  assertDistinctOwnerPubkeys(owners); // §11-8 two-time-pad guard (shared ephemeral key)
  const outCommits = amounts.map((v, i) => commitment(v, outSalt(i), owners[i]));

  const input = {
    nullifiers: [nullifier(V, inSalt, EMPLOYER.formattedPrivateKey)],
    inputCommitments: [inCommit],
    inputValues: [V],
    inputSalts: [inSalt],
    inputOwnerPrivateKey: EMPLOYER.formattedPrivateKey,
    ecdhPrivateKey: ECDH,
    root: tree.getRoot(),
    pathElements: [siblings],
    leafIndices: [BigInt(leafIndex)],
    enabled: [1n],
    outputCommitments: outCommits,
    outputValues: amounts,
    outputSalts: amounts.map((_, i) => outSalt(i)),
    outputOwnerPublicKeys: owners,
    encryptionNonce: NONCE,
    authorityPublicKey: AUTHORITY.publicKey,
  };

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, "disburse256.json"), JSON.stringify(jsonify(input), null, 2));
  console.log(`  wrote inputs/disburse256.json (B=${B}, V=${V}, leaf ${leafIndex})`);
}

main();
