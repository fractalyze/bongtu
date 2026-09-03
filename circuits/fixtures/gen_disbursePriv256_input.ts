// Deterministic witness-input generator for the PRODUCTION 1×256 CONSUMER
// disburse circuit (disbursePriv256, OPMOD §2/§4 — .dev/op-module-design.md).
//
// Writes inputs/disbursePriv256.json — a complete, satisfying circom input for
// circuits/out/disbursePriv256_js — the GPU-proving fixture (CLAUDE.md GPU
// regen recipe) and the prover service's boot warm-up input for the consumer
// batch engine. gen_consumer_inputs.ts covers the 1×16 dev-loop disbursePriv;
// this covers the 1×256.
//
// PRNG-free like the others: the output PLAN (values, salts, 250 distinct
// funded recipients + 6 distinct-throwaway pad slots, OPMOD §4.5) and every
// per-output ML-KEM encapsulation are index-derived through consumer_lib.ts,
// SHARED with the U3 consumer realproof export so the module `disclosure`
// array and kem cts regenerate byte-stable from the same plan. The tree is
// local and SINGLE-LEAF (leaf 0 = the spent input note): the proof verifies
// against the disbursePriv256 vkey with its own self-consistent root, and a
// contracts-side oracle reproduces it with one appendLeaf.
//
//   npx tsx circuits/fixtures/gen_disbursePriv256_input.ts   # writes fixtures/inputs/disbursePriv256.json

import { nullifier, commitment } from "@bongtu/core/note";

import { ECDH_SK, ENCRYPTION_NONCE, SENDER, membership, salt, write } from "./fixture_lib.js";
import { DISBURSE_PRIV256_B, disbursePriv256Plan, outputSide, sealPlan } from "./consumer_lib.js";
import type { ConsumerSpendInput } from "./consumer_lib.js";

function main(): void {
  const plan = disbursePriv256Plan(); // 250 funded + 6 pads (OPMOD §4.5)
  const sealed = sealPlan("disbursePriv256", plan);
  const V = plan.reduce((a, p) => a + p.value, 0n);

  const inSalt = salt(999);
  const inCommit = commitment(V, inSalt, SENDER.publicKey);
  const { root, pathElements, leafIndices } = membership([inCommit]);

  const input: ConsumerSpendInput = {
    nullifiers: [nullifier(V, inSalt, SENDER.formattedPrivateKey)],
    inputCommitments: [inCommit],
    inputValues: [V],
    inputSalts: [inSalt],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [1n], // module-injected constant 1 after ZeroNullifier (OPMOD §2.1)
    ...outputSide(sealed),
    encryptionNonce: ENCRYPTION_NONCE,
  };

  write("disbursePriv256", input);
  console.log(`  (B=${DISBURSE_PRIV256_B}, V=${V})`);
}

main();
