// Value-belt attack fixtures for the consumer tops that CARRY the belt —
// transferPriv, transfer10x2Priv, withdrawPriv (OPMOD §2.1: the
// assert_attacks_throw fixtures "re-target the consumer tops that carry the
// belt"; the consumer disburse base deliberately omits the belt — its
// compensating ZeroNullifier + enabled=1 sequence is a ConsumerDisburseModule
// obligation, so it gets NO belt fixture here).
//
// Mirrors gen_attack_inputs.ts on the consumer shapes:
//
//   withdrawPriv_mint        {nf=0, commitment=0, value=X, enabled=0} -> THROWS
//   withdrawPriv_attack      enabled=[1,0] on a value-carrying input[1] -> THROWS
//   withdrawPriv_padded      genuine zero-value disabled pad -> SUCCEEDS
//   transferPriv_attack      enabled=[1,0] on a value-carrying input[1] -> THROWS
//   transfer10x2Priv_attack  value-carrying DISABLED slot 4 of a 10-input spend -> THROWS
//
// (positive controls for the 10-arity pads: the honest transfer10x2Priv
// fixture from gen_consumer_inputs.ts, 6 zero-value disabled pads.)
//
//   npx tsx circuits/fixtures/gen_consumer_attack_inputs.ts

import { commitment, nullifier } from "@bongtu/core/note";

import { ECDH_SK, ENCRYPTION_NONCE, H, SENDER, membership, salt, write } from "./fixture_lib.js";
import { CONSUMER_SENDER, consumerReceiver, outputSide, sealPlan } from "./consumer_lib.js";
import type {
  ConsumerSpendInput,
  ConsumerWithdrawInput,
  OutputPlan,
} from "./consumer_lib.js";

const RECIPIENT = 0x1111111111111111111111111111111111111111n;

// --- withdrawPriv_mint: the TRUE mint-from-nothing vector -------------------
// nullifier=0 + commitment=0 + value=X + enabled=0 passes CheckNullifiers,
// CheckHashes and (enabled=0) membership, yet the sum adds X unconditionally
// => out pays X from nothing. The module-derived enabled=(nf!=0)=0 AGREES, so
// only the circuit value-belt closes it: `(1-enabled)*value === 0` is
// unsatisfiable at witness-gen.
function genMint(): ConsumerWithdrawInput {
  const X = 1000n;
  const inValues = [X, 0n];
  const inSalts = [salt(30), salt(31)];
  const inCommits = [0n, 0n];
  const { root, pathElements, leafIndices } = membership(inCommits);
  const plan: OutputPlan[] = [{ value: 0n, salt: salt(0), id: CONSUMER_SENDER }];
  const side = outputSide(sealPlan("withdrawPriv_mint", plan));
  return {
    nullifiers: [0n, 0n],
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [0n, 0n],
    ...side,
    // CheckHashes' zero-commitment escape on the OUTPUT side, as in the
    // enterprise mint vector — the belt must reject the INPUT side first.
    outputCommitments: [0n],
    encryptionNonce: ENCRYPTION_NONCE,
    recipient: RECIPIENT,
  };
}

// --- withdrawPriv_attack: enabled=[1,0] but input[1] carries value 500 ------
function genAttack(): ConsumerWithdrawInput {
  const inValues = [600n, 500n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);
  const plan: OutputPlan[] = [{ value: 100n, salt: salt(0), id: CONSUMER_SENDER }];
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
    enabled: [1n, 0n], // input[1] membership SKIPPED though value-carrying => THROWS
    ...outputSide(sealPlan("withdrawPriv_attack", plan)),
    encryptionNonce: ENCRYPTION_NONCE,
    recipient: RECIPIENT,
  };
}

// --- withdrawPriv_padded: genuine zero-value pad in slot 1 -> SUCCEEDS ------
function genPadded(): ConsumerWithdrawInput {
  const inValues = [600n, 0n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);
  const plan: OutputPlan[] = [{ value: 100n, salt: salt(0), id: CONSUMER_SENDER }];
  return {
    nullifiers: [nullifier(600n, inSalts[0], SENDER.formattedPrivateKey), 0n],
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 0n],
    ...outputSide(sealPlan("withdrawPriv_padded", plan)),
    encryptionNonce: ENCRYPTION_NONCE,
    recipient: RECIPIENT,
  };
}

// --- transferPriv_attack: the 2-in twin of genAttack ------------------------
// (the enterprise suite had no 2-in transfer attack fixture; the consumer
// re-target covers every belt-carrying top per OPMOD §2.1.)
function genTransferAttack(): ConsumerSpendInput {
  const inValues = [600n, 500n];
  const inSalts = [salt(20), salt(21)];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);
  // CheckSum equality holds at 1100 (inflated by the skipped input) — only
  // the belt `(1-enabled[1])*500 != 0` is unsatisfiable.
  const plan: OutputPlan[] = [
    { value: 1100n, salt: salt(0), id: consumerReceiver(0) },
    { value: 0n, salt: salt(1), id: CONSUMER_SENDER },
  ];
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
    enabled: [1n, 0n],
    ...outputSide(sealPlan("transferPriv_attack", plan)),
    encryptionNonce: ENCRYPTION_NONCE,
  };
}

// --- transfer10x2Priv_attack: value-carrying DISABLED slot 4 ----------------
function genSpend10Attack(): ConsumerSpendInput {
  const N = 10;
  const real = [400n, 300n, 200n, 100n]; // enabled, 1000 total
  const smuggled = 500n; // slot 4: value-carrying but enabled=0
  const inValues = [...real, smuggled];
  const inSalts = inValues.map((_, i) => salt(40 + i));
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], SENDER.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);

  const nPad = N - inValues.length;
  const padSalts = Array.from({ length: nPad }, (_, i) => salt(80 + i));
  const zerosPath = Array.from({ length: H }, () => 0n);

  const plan: OutputPlan[] = [
    { value: 1500n, salt: salt(50), id: consumerReceiver(0) }, // inflated
    { value: 0n, salt: salt(51), id: CONSUMER_SENDER },
  ];
  return {
    nullifiers: [
      ...inValues.map((v, i) => nullifier(v, inSalts[i], SENDER.formattedPrivateKey)),
      ...padSalts.map(() => 0n),
    ],
    inputCommitments: [...inCommits, ...padSalts.map((s) => commitment(0n, s, SENDER.publicKey))],
    inputValues: [...inValues, ...padSalts.map(() => 0n)],
    inputSalts: [...inSalts, ...padSalts],
    inputOwnerPrivateKey: SENDER.formattedPrivateKey,
    ecdhPrivateKey: BigInt(ECDH_SK),
    root,
    pathElements: [...pathElements, ...padSalts.map(() => zerosPath)],
    leafIndices: [...leafIndices, ...padSalts.map(() => 0n)],
    enabled: [1n, 1n, 1n, 1n, 0n, ...padSalts.map(() => 0n)], // slot 4 skipped though value-carrying
    ...outputSide(sealPlan("transfer10x2Priv_attack", plan)),
    encryptionNonce: ENCRYPTION_NONCE,
  };
}

write("withdrawPriv_mint", genMint());
write("withdrawPriv_attack", genAttack());
write("withdrawPriv_padded", genPadded());
write("transferPriv_attack", genTransferAttack());
write("transfer10x2Priv_attack", genSpend10Attack());
console.log("consumer mint/attack/padded input generation OK");
