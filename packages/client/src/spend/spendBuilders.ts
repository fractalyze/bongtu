// spend/spendBuilders.ts — the transfer / transfer10x2 / transfer10 (deprecated) /
// withdraw ProvingRequest builders + the shared SpendMeta assembly (split from spend.ts).

import { commitment } from "@bongtu/core/note";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { Point } from "@bongtu/core/babyjub";
import {
  toWire,
  type TransferInput,
  type Transfer10Input,
  type Transfer10x2Input,
  type WithdrawInput,
} from "@bongtu/core/proving";
import type { WalletIdentity } from "@bongtu/client/derive";
import { assembleInputs, type AssembledInputs } from "./spendAssemble.js";
import type { MembershipWitness, SpendCrypto, SpendMeta, SpendResult, WalletInputNote } from "./spendPlan.js";

// --- transfer (2-in / 2-out) ----------------------------------------------------

/**
 * Assemble a transfer ProvingRequest: spend 1–2 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. Value is
 * conserved (sum(real inputs) == amount + change). The two output owners MAY
 * coincide (a self-send): the transfer circuit encrypts receiver ciphertext i
 * under encryptionNonce + i (§11-8 v1.1, U-X3), so duplicate owners no longer
 * share a keystream — the old two-time-pad rejection applies only to the
 * shared-nonce disburse path.
 *
 * Throws on: a bad input count, a malformed recipient pubkey, amount <= 0,
 * amount exceeding the input total, or a wrong-length path.
 */
export function buildTransferRequest(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipientCompressed: string,
  amount: string,
  crypto: SpendCrypto,
): SpendResult<"transfer"> {
  if (crypto.payeeSalt === undefined) throw new Error("transfer needs crypto.payeeSalt for the payment output");
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, 2);

  const payee = parsePayee(recipientCompressed);
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  // Fixed output order, mirrored by the circuit's per-output nonces: output 0 =
  // payment (recipient), output 1 = change (wallet). recipient == self is legal.
  const outputOwnerPublicKeys: Point[] = [payee, self.publicKey];
  const payeeSalt = BigInt(crypto.payeeSalt);
  const changeSalt = BigInt(crypto.changeSalt);
  const outputValues = [payVal, changeVal];
  const outputSalts = [payeeSalt, changeSalt];
  const outputCommitments = [
    commitment(payVal, payeeSalt, payee),
    commitment(changeVal, changeSalt, self.publicKey),
  ];

  const inputBig: TransferInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, payVal.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- transfer10x2 (10-in / 2-out) -------------------------------------------------

/** The recipient's point from its compressed form, with a message that names the
 *  field the user typed rather than the crypto that rejected it. */
function parsePayee(recipientCompressed: string): Point {
  try {
    return unpackPubkey(recipientCompressed.trim());
  } catch (e) {
    throw new Error(`recipient pubkey invalid: ${(e as Error).message}`);
  }
}

/**
 * Assemble a transfer10x2 ProvingRequest: spend 1–10 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. The input
 * side is buildTransfer10Request's exactly — extra slots padded (nullifier 0,
 * value 0, enabled 0, zeros path, a value-0 self-owned commitment) — but there
 * are only TWO outputs, the two a spend needs: output 0 the payment, output 1
 * the change. That is the whole point of the circuit: an output is a depth-32
 * IMT append, and transfer10's eight zero-value output pads were pure gas.
 *
 * The two uses, both through this one builder (the shape the committed
 * circuits/fixtures/inputs/transfer10x2_merge.json fixture carries):
 *   - a payment needing 3–10 notes (recipient = the payee, change back home);
 *   - a self-merge (recipient = the wallet's own address, amount = the full
 *     input total), which lands everything in ONE note with a ZERO-value change
 *     note — zero change is legal, the commitment is still nonzero.
 * Duplicate output owners are safe: receiver ciphertext i is encrypted under
 * encryptionNonce + i (§11-8 v1.1), so the shared-keystream ban that applies to
 * disburse does not apply here.
 */
export function buildTransfer10x2Request(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipientCompressed: string,
  amount: string,
  crypto: SpendCrypto,
): SpendResult<"transfer10x2"> {
  if (crypto.payeeSalt === undefined) throw new Error("transfer10x2 needs crypto.payeeSalt for the payment output");
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, TRANSFER10_ARITY);

  const payee = parsePayee(recipientCompressed);
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  // Fixed output order, mirrored by the circuit's per-output nonces: output 0 =
  // payment (or the merged note), output 1 = change (value 0 for a full-total
  // merge — still a real note on its own salt).
  const outputOwnerPublicKeys: Point[] = [payee, self.publicKey];
  const payeeSalt = BigInt(crypto.payeeSalt);
  const changeSalt = BigInt(crypto.changeSalt);
  const outputValues = [payVal, changeVal];
  const outputSalts = [payeeSalt, changeSalt];
  const outputCommitments = [
    commitment(payVal, payeeSalt, payee),
    commitment(changeVal, changeSalt, self.publicKey),
  ];

  const inputBig: Transfer10x2Input = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer10x2", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, payVal.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- transfer10 (10-in / 10-out) — DEPRECATED -------------------------------------

/**
 * @deprecated The wallet routes NOTHING here anymore (user decision 2026-07-28):
 * transfer10 stays deployed on chain, but every >2-input spend and every merge
 * leg proves transfer10x2 above. Kept only for the committed
 * live driver of the (now deprecated) V4 entrypoint used.
 *
 * Assemble a transfer10 ProvingRequest: spend 1–10 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. Same shape as
 * buildTransferRequest at arity 10 — the extra input slots are padded (nullifier 0,
 * value 0, enabled 0, zeros path, a value-0 self-owned commitment) and the extra
 * OUTPUT slots are real value-0 notes back to the wallet, which is exactly what the
 * committed circuits/fixtures/inputs/transfer10.json fixture carries.
 *
 * The two uses, both through this one builder:
 *   - a payment needing 3–10 notes (recipient = the payee);
 *   - a self-merge (recipient = the wallet's own address, amount = the full input
 *     total), which lands everything in ONE note and leaves 9 value-0 notes behind.
 * Duplicate output owners are safe: receiver ciphertext i is encrypted under
 * encryptionNonce + i (§11-8 v1.1), so the shared-keystream ban that applies to
 * disburse does not apply here.
 */
export function buildTransfer10Request(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipientCompressed: string,
  amount: string,
  crypto: SpendCrypto,
): SpendResult<"transfer10"> {
  if (crypto.payeeSalt === undefined) throw new Error("transfer10 needs crypto.payeeSalt for the payment output");
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, TRANSFER10_ARITY);

  const payee = parsePayee(recipientCompressed);
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  const padCount = TRANSFER10_ARITY - 2;
  if (crypto.outputPadSalts.length < padCount) {
    throw new Error(`transfer10 needs ${padCount} outputPadSalts, got ${crypto.outputPadSalts.length}`);
  }
  // Fixed output order, mirrored by the circuit's per-output nonces: output 0 =
  // payment, output 1 = change, outputs 2..9 = value-0 notes back to the wallet.
  const outputOwnerPublicKeys: Point[] = [
    payee,
    ...Array.from({ length: padCount + 1 }, () => self.publicKey),
  ];
  const outputValues = [payVal, changeVal, ...Array.from({ length: padCount }, () => 0n)];
  const outputSalts = [
    BigInt(crypto.payeeSalt),
    BigInt(crypto.changeSalt),
    ...crypto.outputPadSalts.slice(0, padCount).map((s) => BigInt(s)),
  ];
  const outputCommitments = outputValues.map((v, i) => commitment(v, outputSalts[i], outputOwnerPublicKeys[i]));

  const inputBig: Transfer10Input = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer10", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, payVal.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- withdraw (2-in / 1-out) ----------------------------------------------------

/**
 * Assemble a withdraw ProvingRequest: spend 1–2 of the wallet's notes, push `amount`
 * of the underlying ERC-20 to the caller, keep the remainder as a change note. The
 * circuit's `out` public = sum(inputs) - sum(outputs) = amount, so change = total -
 * amount. A full withdrawal leaves a value-0 change note (its commitment is still
 * non-zero, so the contract accepts the append).
 *
 * Throws on: a bad input count, amount <= 0, amount exceeding the input total, or a
 * wrong-length path.
 */
export function buildWithdrawRequest(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  amount: string,
  crypto: SpendCrypto,
  recipient: string,
): SpendResult<"withdraw"> {
  const recipientBig = BigInt(recipient);
  if (recipientBig === 0n || recipientBig > (1n << 160n) - 1n) {
    throw new Error(`withdraw recipient must be a nonzero L1 address, got ${recipient}`);
  }
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, 2);

  const out = BigInt(amount);
  if (out <= 0n) throw new Error(`withdraw amount must be positive, got ${out}`);
  if (out > ins.inputTotal) throw new Error(`amount ${out} exceeds spendable input total ${ins.inputTotal}`);
  const changeVal = ins.inputTotal - out;

  const changeSalt = BigInt(crypto.changeSalt);
  const outputValues = [changeVal];
  const outputSalts = [changeSalt];
  const outputCommitments = [commitment(changeVal, changeSalt, self.publicKey)];
  const outputOwnerPublicKeys: Point[] = [self.publicKey];

  const inputBig: WithdrawInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
    recipient: recipientBig,
  };

  const request = { circuit: "withdraw", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, out.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- shared meta ----------------------------------------------------------------
// (wire decimalisation is sdk toWire — byte-equality with the old per-field
// serializers pinned on the committed fixtures before the swap)

function spendMeta(
  ins: AssembledInputs,
  amount: string,
  changeValue: string,
  outputCommitments: bigint[],
  outputValues: bigint[],
): SpendMeta {
  return {
    inputCommitments: ins.inputCommitments.map((x) => x.toString()),
    nullifiers: ins.nullifiers.map((x) => x.toString()),
    enabled: ins.enabled.map((x) => x.toString()),
    realInputCount: ins.enabled.filter((e) => e === 1n).length,
    inputTotal: ins.inputTotal.toString(),
    amount,
    changeValue,
    membershipOk: ins.membershipOk,
    outputCommitments: outputCommitments.map((x) => x.toString()),
    outputValues: outputValues.map((x) => x.toString()),
  };
}
