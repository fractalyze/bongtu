// ops/consumer/requests.ts — the depositPriv / transferPriv /
// transfer10x2Priv / withdrawPriv ProvingRequest builders.
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import {
  toWire,
  type ConsumerDepositInput,
  type ConsumerSpendInput,
  type ConsumerWithdrawInput,
} from "@bongtu/core/proving";

import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import {
  assembleInputs,
  type AssembledInputs,
  type MembershipWitness,
  type WalletInputNote,
} from "@bongtu/client/spend";
import {
  outputSide,
  planConsumerOutputs,
  sealMeta,
  selfConsumerRecipient,
  type ConsumerDepositCrypto,
  type ConsumerDepositResult,
  type ConsumerRecipient,
  type ConsumerSpendCrypto,
  type ConsumerSpendMeta,
  type ConsumerSpendResult,
  type PlannedConsumerOutput,
} from "./plan.js";
function consumerSpendMeta(
  ins: AssembledInputs,
  amount: string,
  changeValue: string,
  outs: PlannedConsumerOutput[],
): ConsumerSpendMeta {
  return {
    inputCommitments: ins.inputCommitments.map((x) => x.toString()),
    nullifiers: ins.nullifiers.map((x) => x.toString()),
    enabled: ins.enabled.map((x) => x.toString()),
    realInputCount: ins.enabled.filter((e) => e === 1n).length,
    inputTotal: ins.inputTotal.toString(),
    amount,
    changeValue,
    membershipOk: ins.membershipOk,
    outputCommitments: outs.map((o) => o.commitment.toString()),
    outputValues: outs.map((o) => o.value.toString()),
    ...sealMeta(outs),
  };
}

// --- depositPriv (0-in / 2-out) --------------------------------------------------

/** One requested deposit output: who receives, how much. Value 0 is legal (the
 *  "note(V) + note(0)" mint shape uses it) as long as the TOTAL is positive —
 *  a value-0 note is still a real, non-zero commitment. */
export interface ConsumerDepositOutput {
  recipient: ConsumerRecipient;
  value: string;
}

/**
 * Assemble a depositPriv ProvingRequest: mint TWO output notes, each to ANY
 * consumer recipient — third parties included, which is the consumer deposit's
 * whole point (the enterprise deposit can only mint to the depositor because it
 * publishes no per-recipient ciphertext; this one seals per output, so the
 * recipient discovers the mint by scan). The on-chain `out` public (pub[0])
 * equals the value total the pool pulls.
 *
 * Throws on an output count != 2 (the circuit arity), a negative value, or a
 * non-positive total.
 */
export function buildConsumerDepositRequest(
  outputs: ConsumerDepositOutput[],
  crypto: ConsumerDepositCrypto,
): ConsumerDepositResult {
  if (outputs.length !== 2) {
    throw new Error(`depositPriv mints exactly 2 outputs, got ${outputs.length}`);
  }
  const values = outputs.map((o) => BigInt(o.value));
  for (const [i, v] of values.entries()) {
    if (v < 0n) throw new Error(`deposit output ${i} value must be non-negative, got ${v}`);
  }
  const total = values[0] + values[1];
  if (total <= 0n) throw new Error(`deposit total must be positive, got ${total}`);

  const salts = [BigInt(crypto.salt0), BigInt(crypto.salt1)];
  const outs = planConsumerOutputs(
    outputs.map((o, i) => ({ recipient: o.recipient, value: values[i], salt: salts[i] })),
    crypto,
  );

  const inputBig: ConsumerDepositInput = {
    ...outputSide(outs),
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    encryptionNonce: BigInt(crypto.encryptionNonce),
  };

  const request = { circuit: "depositPriv", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: {
      outputCommitments: outs.map((o) => o.commitment.toString()),
      outputValues: outs.map((o) => o.value.toString()),
      amount: total.toString(),
      ...sealMeta(outs),
    },
  };
}

// --- transferPriv / transfer10x2Priv (n-in / 2-out) ------------------------------

/** The shared 2-output spend core: input side via spend.ts assembleInputs (the
 *  untyped-note algebra), output 0 = payment sealed to the recipient triple,
 *  output 1 = change sealed to the wallet's own triple — the pinned output
 *  order every consumer transfer fixture carries. */
function consumerTransferParts(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipient: ConsumerRecipient,
  amount: string,
  crypto: ConsumerSpendCrypto,
  arity: number,
): { input: ConsumerSpendInput; meta: ConsumerSpendMeta } {
  if (crypto.payeeSalt === undefined) {
    throw new Error("a consumer transfer needs crypto.payeeSalt for the payment output");
  }
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, arity);

  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  const outs = planConsumerOutputs(
    [
      { recipient, value: payVal, salt: BigInt(crypto.payeeSalt) },
      {
        recipient: selfConsumerRecipient(identity),
        value: changeVal,
        salt: BigInt(crypto.changeSalt),
      },
    ],
    crypto,
  );

  const input: ConsumerSpendInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: identity.keypair.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    ...outputSide(outs),
    encryptionNonce: BigInt(crypto.encryptionNonce),
  };
  return { input, meta: consumerSpendMeta(ins, payVal.toString(), changeVal.toString(), outs) };
}

/**
 * Assemble a transferPriv ProvingRequest: spend 1–2 of the wallet's notes, pay
 * the recipient triple `amount`, seal the change back to the wallet. Value is
 * conserved (sum(real inputs) == amount + change); recipient == self is legal
 * (per-output nonce, OPMOD §3.5).
 */
export function buildConsumerTransferRequest(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipient: ConsumerRecipient,
  amount: string,
  crypto: ConsumerSpendCrypto,
): ConsumerSpendResult<"transferPriv"> {
  const { input, meta } = consumerTransferParts(
    identity,
    inputs,
    memberships,
    recipient,
    amount,
    crypto,
    2,
  );
  return { request: { circuit: "transferPriv", input: toWire(input), backend: "cpu" }, meta };
}

/**
 * Assemble a transfer10x2Priv ProvingRequest: the 3–10-note consolidation/spend
 * (and the merge leg of a consumer chain — a self-send where the recipient is
 * the wallet's own triple). Input side identical to the enterprise
 * transfer10x2: unused slots padded {nullifier 0, value 0, enabled 0, zeros
 * path, a value-0 self-owned commitment on its own salt}.
 */
export function buildConsumerTransfer10x2Request(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipient: ConsumerRecipient,
  amount: string,
  crypto: ConsumerSpendCrypto,
): ConsumerSpendResult<"transfer10x2Priv"> {
  const { input, meta } = consumerTransferParts(
    identity,
    inputs,
    memberships,
    recipient,
    amount,
    crypto,
    TRANSFER10_ARITY,
  );
  return { request: { circuit: "transfer10x2Priv", input: toWire(input), backend: "cpu" }, meta };
}

// --- withdrawPriv (2-in / 1-out + recipient) -------------------------------------

/**
 * Assemble a withdrawPriv ProvingRequest: spend 1–2 notes, push `amount` of the
 * ERC-20 to the proof-bound L1 `recipient`, seal the change note back to the
 * wallet (a full withdrawal leaves a value-0 change note — still a non-zero
 * commitment). The recipient is bound IN-PROOF so a relayer cannot redirect the
 * payout; the module range-checks the same slot on-chain (OPMOD §2).
 */
export function buildConsumerWithdrawRequest(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  amount: string,
  crypto: ConsumerSpendCrypto,
  recipient: string,
): ConsumerSpendResult<"withdrawPriv"> {
  const recipientBig = BigInt(recipient);
  // Rail-agnostic bound (2026-09-05, the Solana client landing): `recipient`
  // is ONE field element the circuit binds verbatim; each rail narrows it at
  // its own chain edge (the EVM module range-checks uint160 on-chain, the
  // Solana program injects truncate-253 of the recipient token account —
  // recipient_binding.rs), so the builder's belt is the widest any rail can
  // bind: nonzero and under 2^253. An EVM caller's mistyped over-wide address
  // now fails at the module's on-chain range check instead of here.
  if (recipientBig === 0n || recipientBig >> 253n !== 0n) {
    throw new Error(`withdraw recipient must be a nonzero proof-bindable address, got ${recipient}`);
  }
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, 2);

  const out = BigInt(amount);
  if (out <= 0n) throw new Error(`withdraw amount must be positive, got ${out}`);
  if (out > ins.inputTotal) {
    throw new Error(`amount ${out} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - out;

  const outs = planConsumerOutputs(
    [
      {
        recipient: selfConsumerRecipient(identity),
        value: changeVal,
        salt: BigInt(crypto.changeSalt),
      },
    ],
    crypto,
  );

  const inputBig: ConsumerWithdrawInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: identity.keypair.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    ...outputSide(outs),
    encryptionNonce: BigInt(crypto.encryptionNonce),
    recipient: recipientBig,
  };

  const request = { circuit: "withdrawPriv", input: toWire(inputBig), backend: "cpu" } as const;
  return { request, meta: consumerSpendMeta(ins, out.toString(), changeVal.toString(), outs) };
}
