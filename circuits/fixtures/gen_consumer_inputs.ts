// Deterministic witness-input generator for the 5 CPU consumer circuits
// (OPMOD §2, .dev/op-module-design.md): depositPriv, transferPriv,
// transfer10x2Priv, withdrawPriv, disbursePriv (the 1×16 dev-loop twin;
// disbursePriv256 is compile-only in this unit — GPU regen recipe applies
// when it ships).
//
// PRNG-free like gen_inputs.ts: every scalar / salt / nonce / KEM seed is
// index-derived through fixture_lib.ts + consumer_lib.ts, so regenerating
// leaves a clean tree. The output PLANS (values, salts, identities) and the
// per-output ML-KEM encapsulations live in consumer_lib.ts, SHARED with the
// consumer gates — the gates re-derive the same seals to run the OPMOD §3.6
// discovery pipeline (viewTag filter -> Decaps -> decrypt -> leaf-match)
// against the artifacts these inputs prove.
//
//   npx tsx circuits/fixtures/gen_consumer_inputs.ts   # writes fixtures/inputs/<name>Priv.json x5

import { nullifier, commitment } from "@bongtu/core/note";

import {
  ECDH_SK,
  ENCRYPTION_NONCE,
  H,
  SENDER,
  membership,
  salt,
  write,
} from "./fixture_lib.js";
import {
  depositPrivPlan,
  disbursePrivPlan,
  outputSide,
  sealPlan,
  transfer10x2PrivPlan,
  transferPrivPlan,
  withdrawPrivPlan,
} from "./consumer_lib.js";
import type {
  ConsumerDepositInput,
  ConsumerSpendInput,
  ConsumerWithdrawInput,
} from "./consumer_lib.js";

// --- depositPriv (0-in / 2-out), BongtuConsumerDeposit(2) -------------------

function genDepositPriv(): ConsumerDepositInput {
  const sealed = sealPlan("depositPriv", depositPrivPlan());
  return {
    ...outputSide(sealed),
    ecdhPrivateKey: BigInt(ECDH_SK),
    encryptionNonce: ENCRYPTION_NONCE,
  };
}

// --- transferPriv (2-in / 2-out), BongtuConsumerTransfer(2,2,32) ------------

function genTransferPriv(): ConsumerSpendInput {
  const inValues = [700n, 300n];
  const inSalts = [salt(10), salt(11)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const sealed = sealPlan("transferPriv", transferPrivPlan()); // 600 + 400 == 700 + 300
  return {
    nullifiers: inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 1n],
    ...outputSide(sealed),
    encryptionNonce: ENCRYPTION_NONCE,
  };
}

// --- transfer10x2Priv (10-in / 2-out), BongtuConsumerTransfer(10,2,32) ------
//
// Padding convention mirrored from gen_inputs.ts spend10: an unused input slot
// carries nullifier 0, value 0, enabled 0, a zeros path and a NONZERO value-0
// commitment owned by the sender.

const ZEROS_PATH = Array.from({ length: H }, () => 0n);

function genTransfer10x2Priv(): ConsumerSpendInput {
  const N = 10;
  const inValues = [400n, 300n, 200n, 100n]; // 1000 spendable
  const inSalts = inValues.map((_, i) => salt(100 + i));
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const pads = Array.from({ length: N - inValues.length }, (_, i) => {
    const s = salt(80 + i);
    return { nullifier: 0n, commitment: commitment(0n, s, SENDER.publicKey), value: 0n, salt: s };
  });

  const sealed = sealPlan("transfer10x2Priv", transfer10x2PrivPlan()); // 700 + 300 == 1000
  return {
    nullifiers: [
      ...inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
      ...pads.map((p) => p.nullifier),
    ],
    inputCommitments: [...inCommits, ...pads.map((p) => p.commitment)],
    inputValues: [...inValues, ...pads.map((p) => p.value)],
    inputSalts: [...inSalts, ...pads.map((p) => p.salt)],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements: [...pathElements, ...pads.map(() => ZEROS_PATH)],
    leafIndices: [...leafIndices, ...pads.map(() => 0n)],
    enabled: [...inValues.map(() => 1n), ...pads.map(() => 0n)],
    ...outputSide(sealed),
    encryptionNonce: ENCRYPTION_NONCE,
  };
}

// --- withdrawPriv (2-in / 1-out + recipient), BongtuWithdrawPriv(2,1,32) ----

function genWithdrawPriv(): ConsumerWithdrawInput {
  const inValues = [600n, 500n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  // change 100 back to the sender; out = 1100 - 100 = 1000 ERC-20 pushed.
  const sealed = sealPlan("withdrawPriv", withdrawPrivPlan());
  return {
    nullifiers: inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 1n],
    ...outputSide(sealed),
    encryptionNonce: ENCRYPTION_NONCE,
    recipient: 0x1111111111111111111111111111111111111111n,
  };
}

// --- disbursePriv (1-in / 16-out), BongtuConsumerDisburse(1,16,32) ----------

function genDisbursePriv(): ConsumerSpendInput {
  const plan = disbursePrivPlan(); // 12 funded + 4 pads (OPMOD §4.5)
  const sealed = sealPlan("disbursePriv", plan);
  const V = plan.reduce((a, p) => a + p.value, 0n);

  const inSalt = salt(99);
  const inCommit = commitment(V, inSalt, SENDER.publicKey);
  const { root, pathElements, leafIndices } = membership([inCommit]);

  return {
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
}

write("depositPriv", genDepositPriv());
write("transferPriv", genTransferPriv());
write("transfer10x2Priv", genTransfer10x2Priv());
write("withdrawPriv", genWithdrawPriv());
write("disbursePriv", genDisbursePriv());
console.log("consumer input generation OK");
