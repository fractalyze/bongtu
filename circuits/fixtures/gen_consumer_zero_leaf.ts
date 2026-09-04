// §5.2 zero-leaf soundness fixtures for the FOUR consumer spending circuits
// (OPMOD §2.1 gate obligation: test_zero_leaf_unsat.sh "extends to all four
// consumer SPENDING circuits" — transferPriv, transfer10x2Priv, withdrawPriv,
// and the consumer disburse base via its 1×16 dev-loop twin disbursePriv;
// disbursePriv256 shares the identical BongtuConsumerDisburse template, so the
// small arity is the CPU-tractable witness of the same belt).
//
// The exploit is gen_zero_leaf_inputs.ts's verbatim: in the index-keyed IMT,
// zeros[0]=0 is a GENUINE membership-provable leaf, so an input
// {commitment: 0, value: X, enabled: 1, fresh nullifier, genuine
// zeros-membership} passes every constraint EXCEPT the zero-commitment belt
// `enabled[i] * IsZero(inputCommitments[i]) === 0`, which each consumer base
// carries over verbatim (OPMOD §2.1 REQUIRED column). Every other constraint
// is deliberately satisfied so witness-gen fails on exactly that belt and the
// assertion string names the consumer base template.
//
//   npx tsx circuits/fixtures/gen_consumer_zero_leaf.ts
//     # writes fixtures/inputs/{transferPriv,transfer10x2Priv,withdrawPriv,disbursePriv}_zero_leaf.json

import { commitment, nullifier } from "@bongtu/core/note";

import { ECDH_SK, ENCRYPTION_NONCE, SENDER, ZERO_PATH, ZERO_ROOT, salt, write } from "./fixture_lib.js";
import { CONSUMER_SENDER, consumerReceiver, outputSide, sealPlan } from "./consumer_lib.js";
import type {
  ConsumerSpendInput,
  ConsumerWithdrawInput,
  OutputPlan,
} from "./consumer_lib.js";

// The arbitrary value the attacker mints from a padded 0-leaf they never
// deposited — within the 100-bit range so CheckPositive witness-gen succeeds.
const X = 1000000000000n; // 1e12

// input0: the exploit (commitment 0, value X, enabled 1, fresh nullifier).
const exploitInput0 = {
  nullifier: nullifier(X, salt(30), SENDER.formattedPrivateKey), // != 0 => module-derived enabled=1
  commitment: 0n, // CheckHashes escape leaves value unbound
  value: X,
  salt: salt(30),
  leafIndex: 0n, // a genuine zeros position
  path: ZERO_PATH,
};

// input1: a genuine DISABLED pad (belt vacuous at enabled=0 — only input0 trips).
const padInput1 = {
  nullifier: 0n,
  commitment: 0n,
  value: 0n,
  salt: salt(31),
  leafIndex: 0n,
  path: ZERO_PATH,
};

const spendSide = (
  inputs: typeof exploitInput0[],
  enabled: bigint[],
): Pick<
  ConsumerSpendInput,
  | "nullifiers"
  | "inputCommitments"
  | "inputValues"
  | "inputSalts"
  | "inputOwnerPrivateKey"
  | "ecdhPrivateKey"
  | "root"
  | "pathElements"
  | "leafIndices"
  | "enabled"
  | "encryptionNonce"
> => ({
  nullifiers: inputs.map((x) => x.nullifier),
  inputCommitments: inputs.map((x) => x.commitment),
  inputValues: inputs.map((x) => x.value),
  inputSalts: inputs.map((x) => x.salt),
  inputOwnerPrivateKey: SENDER.formattedPrivateKey,
  ecdhPrivateKey: BigInt(ECDH_SK),
  root: ZERO_ROOT,
  pathElements: inputs.map((x) => x.path),
  leafIndices: inputs.map((x) => x.leafIndex),
  enabled,
  encryptionNonce: ENCRYPTION_NONCE,
});

// --- transferPriv (2-in / 2-out): outputs sum to X so CheckSum passes -------
function genTransferPrivZeroLeaf(): ConsumerSpendInput {
  const plan: OutputPlan[] = [
    { value: X, salt: salt(0), id: consumerReceiver(0) },
    { value: 0n, salt: salt(1), id: CONSUMER_SENDER },
  ];
  return {
    ...spendSide([exploitInput0, padInput1], [1n, 0n]), // enabled at a zero commitment => UNSAT
    ...outputSide(sealPlan("transferPriv_zero_leaf", plan)),
  };
}

// --- transfer10x2Priv: the exploit hides in a PADDED middle slot (7 of 10) --
const EXPLOIT_SLOT = 7;

function genTransfer10x2PrivZeroLeaf(): ConsumerSpendInput {
  const N = 10;
  const inputs = Array.from({ length: N }, (_, i) => (i === EXPLOIT_SLOT ? exploitInput0 : padInput1));
  const enabled = Array.from({ length: N }, (_, i) => (i === EXPLOIT_SLOT ? 1n : 0n));
  const plan: OutputPlan[] = [
    { value: X, salt: salt(0), id: consumerReceiver(0) },
    { value: 0n, salt: salt(1), id: CONSUMER_SENDER },
  ];
  return {
    ...spendSide(inputs, enabled),
    ...outputSide(sealPlan("transfer10x2Priv_zero_leaf", plan)),
  };
}

// --- withdrawPriv (2-in / 1-out): out = X paid from nothing -----------------
function genWithdrawPrivZeroLeaf(): ConsumerWithdrawInput {
  const plan: OutputPlan[] = [{ value: 0n, salt: salt(0), id: CONSUMER_SENDER }];
  return {
    ...spendSide([exploitInput0, padInput1], [1n, 0n]),
    ...outputSide(sealPlan("withdrawPriv_zero_leaf", plan)),
    recipient: 0x1111111111111111111111111111111111111111n,
  };
}

// --- disbursePriv (1-in / 16-out): single module-forced enabled=1 input -----
function genDisbursePrivZeroLeaf(): ConsumerSpendInput {
  const N = 16;
  const plan: OutputPlan[] = Array.from({ length: N }, (_, i) => ({
    value: i === 0 ? X : 0n, // sum == X so CheckSum passes; only the belt is UNSAT
    salt: salt(200 + i),
    id: consumerReceiver(i),
  }));
  return {
    ...spendSide([exploitInput0], [1n]),
    ...outputSide(sealPlan("disbursePriv_zero_leaf", plan)),
  };
}

write("transferPriv_zero_leaf", genTransferPrivZeroLeaf());
write("transfer10x2Priv_zero_leaf", genTransfer10x2PrivZeroLeaf());
write("withdrawPriv_zero_leaf", genWithdrawPrivZeroLeaf());
write("disbursePriv_zero_leaf", genDisbursePrivZeroLeaf());
console.log("consumer zero-leaf exploit input generation OK");
