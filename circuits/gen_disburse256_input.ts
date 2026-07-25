// Deterministic witness-input generator for the PRODUCTION 1×256 disburse circuit.
//
// Writes inputs/disburse256.json — a complete, satisfying circom input for
// circuits/out/disburse256_js — used as the prover service's boot warm-up proof
// (prover/README.md) and as the repo-native fixture for exercising the service
// end-to-end. gen_inputs.ts covers the M0 1×16 dev build; this covers the 1×256.
//
// PRNG-free like the others, but the employer / recipient / ECDH seeds stay
// LOCAL because they mirror deploy/giwa_disburse256.ts (the live runner), not
// the shared gen_inputs material; only AUTHORITY / write() come from
// fixture_lib.ts. The tree here is local (leaf 0 a dummy note, leaf 1 the spent
// input note) — the proof verifies against the disburse256 vkey with its own
// self-consistent root, no chain state involved.
//
//   npx tsx gen_disburse256_input.ts     # writes inputs/disburse256.json

import { ImtTree } from "@bongtu/core/imt";
import { deriveKeypair, commitment, nullifier, assertDistinctOwnerPubkeys } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import type { DisburseInput } from "@bongtu/core/proving";

import { AUTHORITY, H, write } from "./fixture_lib.js";

const B = 256; // production disburse batch size

// deploy/giwa_disburse256.ts key material (deterministic, PRNG-free).
const EMPLOYER = deriveKeypair(313131313131313131313131n);
const recipient = (i: number): Keypair => deriveKeypair(4000000019n + BigInt(i) * 1000003n);
const ECDH = 900000000000000000007n;
const NONCE = 424242424243n;
const inSalt = 8000001n;
const outSalt = (i: number): bigint => 9000000n + BigInt(i);

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

  const input: DisburseInput = {
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

  write("disburse256", input);
  console.log(`  (B=${B}, V=${V}, leaf ${leafIndex})`);
}

main();
