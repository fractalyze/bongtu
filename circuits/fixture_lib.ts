// Shared fixture preamble for the circuits/ witness-input generators.
//
// The five generators (gen_inputs, gen_attack_inputs, gen_zero_leaf_inputs,
// gen_disburse_zero_leaf, gen_disburse256_input) used to transcribe this
// material by hand, synchronized only by "same material as gen_inputs.ts"
// comments. It lives here ONCE so consistency is structural:
//
//   - the fixed, PRNG-free key material (every scalar / salt / nonce is
//     index-derived, so regenerating fixtures is byte-deterministic), including
//     THE single AUTHORITY (arbiter) keypair — every fixture's authority
//     envelope encrypts to this one key by construction, which is what lets
//     contracts/test/fixtures/gen_realproofs.ts inject one stored arbiter key
//     for all four real proofs (its runtime cross-checks remain as a belt);
//   - membership(): real ImtTree witnesses (root / pathElements / leafIndices);
//   - the zeros path (ZERO_ROOT / ZERO_PATH): a genuine empty-tree membership
//     proof of the 0-leaf, the raw material of the §5.2 zero-leaf soundness
//     fixtures;
//   - write(): toWire (bigint -> decimal string) + pretty JSON into inputs/.
//
// gen_disburse256_input.ts keeps its own employer/recipient/ECDH material local
// (it mirrors deploy/giwa_disburse256.ts) but shares AUTHORITY / H / write().

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/sdk/imt";
import { deriveKeypair } from "@bongtu/sdk/note";
import type { Keypair } from "@bongtu/sdk/note";
import { toWire } from "@bongtu/sdk/proving";

const HERE = dirname(fileURLToPath(import.meta.url));
export const OUT_DIR = join(HERE, "inputs");

export const H = 32; // IMT depth (all circuits)

// --- fixed test material (index-derived, PRNG-free) ------------------------

/** The sender owns every spent input note (the base uses one inputOwnerPrivateKey). */
export const SENDER = deriveKeypair(
  2736030358979909402780800718157159386076813972158567259200215660948447373041n - 12345n,
);

/** Ephemeral ECDH key for output/authority encryption. */
export const ECDH_SK = 987654321987654321987654321n;

/** THE fixture authority (arbiter) keypair. One constant, one key: every
 *  generator's authority envelope encrypts to it, so "all fixture proofs share
 *  one arbiter key" holds by construction. */
export const AUTHORITY = deriveKeypair(555555555555555555555555n);

export const ENCRYPTION_NONCE = 424242424242n; // < 2^128

/** Distinct receiver keypair per output index (distinct scalars => distinct pubkeys). */
export function receiver(i: number): Keypair {
  return deriveKeypair(1000000007n + BigInt(i) * 1000003n);
}

export const salt = (i: number): bigint => 1000000n + BigInt(i);

// --- output ----------------------------------------------------------------

/** Wire-encode (bigint -> decimal string) and write inputs/<name>.json. */
export function write(name: string, obj: unknown): void {
  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(join(OUT_DIR, `${name}.json`), JSON.stringify(toWire(obj), null, 2));
  console.log(`  wrote inputs/${name}.json`);
}

// --- membership witnesses --------------------------------------------------

export interface Membership {
  root: bigint;
  pathElements: bigint[][];
  leafIndices: bigint[];
}

/** Insert `commitments` as single leaves into a fresh tree and return the root +
 *  per-leaf { leafIndices, pathElements } membership witness (index-keyed IMT).
 *  The tree is the SAME single-frontier IMT the contract (U3) and e2e (U4) use,
 *  so the membership witnesses stay consistent. */
export function membership(commitments: bigint[]): Membership {
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

// --- the zeros path (§5.2 zero-leaf fixtures) ------------------------------

// A genuine membership proof of the 0-leaf at index 0 of an EMPTY tree:
// root = zeros[H], siblings = zeros[0..H-1]. Folding leaf 0 up with these zeros
// siblings reproduces zeros[H] exactly, so CheckIMTProof holds at enabled=1.
const emptyTree = new ImtTree(H, 16);
export const ZERO_ROOT = emptyTree.getRoot(); // == zeros[H]
export const ZERO_PATH = emptyTree.zeros.slice(0, H); // zeros[0..H-1], length H
