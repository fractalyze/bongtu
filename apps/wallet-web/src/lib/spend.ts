// PURE wallet-side witness assembly for the two small CPU circuits the public app
// proves in the browser: transfer (2-in / 2-out) and withdraw (2-in / 1-out), SPEC
// §4 / §7. Framework- and network-free so the exact code runs in the browser view
// AND the headless spend-witness gate. It imports the sdk crypto DIRECTLY, so every
// commitment / nullifier is byte-identical to what snarkjs proves and the contract
// verifies — the witness objects produced here are EXACTLY the circom `main` inputs
// deploy/e2e_orchestrator.ts assembles by hand, in ProvingRequest form (@bongtu/sdk/proving).
//
// What it does NOT do (SPEC §6 boundary): it does not prove (browser snarkjs, see
// prove.ts) and does not send the tx (MetaMask, see metamask.ts). It stops at "a
// valid transfer/withdraw ProvingRequest", ready to prove and submit.
//
// Both circuits take TWO inputs; a wallet with one note to spend pads input[1] with
// {nullifier:0, value:0, enabled:0, path:zeros} — the contract-derived enabled=0
// disables its membership and the §5.2 value-belt forces its value to 0 (no mint).
// Transfer/withdraw emit their ciphertext as circuit outputs (public signals), so —
// unlike disburse — the wallet assembles NO separate ciphertext blob; the tx is
// just (a, b, c, pub).

import {
  deriveKeypair,
  commitment,
  nullifier,
  assertDistinctOwnerPubkeys,
} from "@bongtu/sdk/note";
import { unpackPubkey } from "@bongtu/sdk/pubkey";
import { poseidon2 } from "@bongtu/sdk/poseidon";
import type { Point } from "@bongtu/sdk/babyjub";
import type {
  TransferInput,
  WithdrawInput,
  ProvingRequest,
} from "@bongtu/sdk/proving";
import type { WalletIdentity } from "./derive.js";
import { H } from "../config.js";

// --- app-facing input shapes (all field elements as decimal strings) ------------

/** An unspent note the wallet owns, as surfaced by the balance view. The wallet is
 *  the owner, so the spending key is the derived identity — not carried per note. */
export interface WalletInputNote {
  value: string;
  salt: string;
  leafIndex: number;
}

/** Membership of one input note against the live root (from GET /path/{leafIndex}). */
export interface MembershipWitness {
  root: string;
  /** length-H (32) merkle siblings of the note against `root`. */
  pathElements: string[];
  leafIndex: number;
}

/** Fresh per-tx crypto material. `ecdhPrivateKey`/`encryptionNonce` must never be
 *  reused across txs (a shared ephemeral key + nonce is a two-time pad). */
export interface SpendCrypto {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** the pool's stored arbiter PUBLIC key — the authority envelope target (§6b v2). */
  authorityPubKey: [string, string];
  /** salt for the change note back to the wallet. */
  changeSalt: string;
  /** salt for the padded (value-0) input note when only one real note is spent. */
  padSalt: string;
  /** transfer only: salt for the payment output to the recipient. */
  payeeSalt?: string;
}

export interface SpendMeta {
  /** recomputed input commitments (real inputs then, if padded, the value-0 note). */
  inputCommitments: string[];
  /** nullifiers per input (0 for the padded input). */
  nullifiers: string[];
  enabled: string[];
  realInputCount: number;
  inputTotal: string;
  /** transfer: amount paid to the recipient. withdraw: ERC20 amount out. */
  amount: string;
  changeValue: string;
  /** every real input's path folds to the shared root. */
  membershipOk: boolean;
  outputCommitments: string[];
  outputValues: string[];
}

export interface SpendResult<C extends "transfer" | "withdraw"> {
  request: Extract<ProvingRequest, { circuit: C }>;
  meta: SpendMeta;
}

// --- helpers -------------------------------------------------------------------

// Fold a leaf up an IMT auth path, taking left/right from the bits of leafIndex —
// bit j == 1 means the sibling is the LEFT child at level j. Mirrors ImtTree.
function foldToRoot(leaf: bigint, siblings: bigint[], leafIndex: number): bigint {
  let cur = leaf;
  let idx = leafIndex;
  for (let j = 0; j < siblings.length; j++) {
    cur = idx % 2 === 1 ? poseidon2(siblings[j], cur) : poseidon2(cur, siblings[j]);
    idx = Math.floor(idx / 2);
  }
  return cur;
}

const dec = (x: bigint | number | string): string => BigInt(x).toString();
const decPoint = (p: readonly [bigint | number | string, bigint | number | string]): [string, string] => [
  dec(p[0]),
  dec(p[1]),
];

// The 2-input membership witness shared by transfer + withdraw: recompute each real
// input's commitment + nullifier from the wallet key, pad input[1] to a value-0 note
// when only one real note is spent, and fold every real input to the shared root.
interface TwoInputs {
  nullifiers: bigint[];
  inputCommitments: bigint[];
  inputValues: bigint[];
  inputSalts: bigint[];
  enabled: bigint[];
  pathElements: bigint[][];
  leafIndices: bigint[];
  root: bigint;
  inputTotal: bigint;
  membershipOk: boolean;
}

function assembleInputs(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  padSalt: bigint,
): TwoInputs {
  if (inputs.length < 1 || inputs.length > 2) {
    throw new Error(`spend takes 1 or 2 input notes, got ${inputs.length}`);
  }
  if (memberships.length !== inputs.length) {
    throw new Error(`need one membership witness per input: ${memberships.length} != ${inputs.length}`);
  }
  const self = identity.keypair;
  const zeros: bigint[] = new Array(H).fill(0n);

  // All real inputs must be proven against ONE root (the live root). Take it from the
  // first membership and require the rest agree.
  const root = BigInt(memberships[0].root);
  for (const m of memberships) {
    if (BigInt(m.root) !== root) throw new Error("all input memberships must share one root");
    if (m.pathElements.length !== H) {
      throw new Error(`pathElements must have length ${H}, got ${m.pathElements.length}`);
    }
  }

  const nullifiers: bigint[] = [];
  const inputCommitments: bigint[] = [];
  const inputValues: bigint[] = [];
  const inputSalts: bigint[] = [];
  const enabled: bigint[] = [];
  const pathElements: bigint[][] = [];
  const leafIndices: bigint[] = [];
  let inputTotal = 0n;
  let membershipOk = true;

  inputs.forEach((note, i) => {
    const v = BigInt(note.value);
    const s = BigInt(note.salt);
    if (v < 0n) throw new Error(`input #${i + 1} value must be non-negative, got ${v}`);
    const c = commitment(v, s, self.publicKey);
    const nf = nullifier(v, s, self.formattedPrivateKey);
    const path = memberships[i].pathElements.map((x) => BigInt(x));
    if (foldToRoot(c, path, memberships[i].leafIndex) !== root) membershipOk = false;
    nullifiers.push(nf);
    inputCommitments.push(c);
    inputValues.push(v);
    inputSalts.push(s);
    enabled.push(1n);
    pathElements.push(path);
    leafIndices.push(BigInt(memberships[i].leafIndex));
    inputTotal += v;
  });

  // Pad input[1] to a value-0 note owned by the wallet: nullifier 0, enabled 0, zeros
  // path (its membership is disabled; the value belt forces value 0 -> no mint).
  if (inputs.length === 1) {
    nullifiers.push(0n);
    inputCommitments.push(commitment(0n, padSalt, self.publicKey));
    inputValues.push(0n);
    inputSalts.push(padSalt);
    enabled.push(0n);
    pathElements.push(zeros);
    leafIndices.push(0n);
  }

  return {
    nullifiers,
    inputCommitments,
    inputValues,
    inputSalts,
    enabled,
    pathElements,
    leafIndices,
    root,
    inputTotal,
    membershipOk,
  };
}

// --- transfer (2-in / 2-out) ----------------------------------------------------

/**
 * Assemble a transfer ProvingRequest: spend 1–2 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. Value is
 * conserved (sum(real inputs) == amount + change), and the two output owners
 * (recipient, wallet) must be distinct — a self-pay would be a two-time pad (§11-8).
 *
 * Throws on: a bad input count, a malformed recipient pubkey, amount <= 0, amount
 * exceeding the input total, a self-transfer, or a wrong-length path.
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
  const ins = assembleInputs(identity, inputs, memberships, BigInt(crypto.padSalt));

  let payee: Point;
  try {
    payee = unpackPubkey(recipientCompressed.trim());
  } catch (e) {
    throw new Error(`recipient pubkey invalid: ${(e as Error).message}`);
  }
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  const outputOwnerPublicKeys: Point[] = [payee, self.publicKey];
  assertDistinctOwnerPubkeys(outputOwnerPublicKeys); // recipient != self (§11-8)
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
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer", input: toDecimalTransfer(inputBig), backend: "cpu" } as const;
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
): SpendResult<"withdraw"> {
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, BigInt(crypto.padSalt));

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
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "withdraw", input: toDecimalWithdraw(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, out.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- shared meta + decimalisation ----------------------------------------------

function spendMeta(
  ins: TwoInputs,
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

// Convert bigint-typed inputs to the decimal-string form that survives JSON.stringify
// (a serialized ProvingRequest has no bigints). Provers accept decimal strings as
// FieldInput as-is.
function toDecimalTransfer(input: TransferInput): TransferInput {
  return {
    nullifiers: input.nullifiers.map(dec),
    inputCommitments: input.inputCommitments.map(dec),
    inputValues: input.inputValues.map(dec),
    inputSalts: input.inputSalts.map(dec),
    inputOwnerPrivateKey: dec(input.inputOwnerPrivateKey),
    ecdhPrivateKey: dec(input.ecdhPrivateKey),
    root: dec(input.root),
    pathElements: (input.pathElements as (bigint | number | string)[][]).map((row) => row.map(dec)),
    leafIndices: input.leafIndices.map(dec),
    enabled: input.enabled.map(dec),
    outputCommitments: input.outputCommitments.map(dec),
    outputValues: input.outputValues.map(dec),
    outputSalts: input.outputSalts.map(dec),
    outputOwnerPublicKeys: input.outputOwnerPublicKeys.map(decPoint),
    encryptionNonce: dec(input.encryptionNonce),
    authorityPublicKey: decPoint(input.authorityPublicKey),
  };
}

function toDecimalWithdraw(input: WithdrawInput): WithdrawInput {
  return {
    nullifiers: input.nullifiers.map(dec),
    inputCommitments: input.inputCommitments.map(dec),
    inputValues: input.inputValues.map(dec),
    inputSalts: input.inputSalts.map(dec),
    inputOwnerPrivateKey: dec(input.inputOwnerPrivateKey),
    root: dec(input.root),
    pathElements: (input.pathElements as (bigint | number | string)[][]).map((row) => row.map(dec)),
    leafIndices: input.leafIndices.map(dec),
    enabled: input.enabled.map(dec),
    outputCommitments: input.outputCommitments.map(dec),
    outputValues: input.outputValues.map(dec),
    outputSalts: input.outputSalts.map(dec),
    outputOwnerPublicKeys: input.outputOwnerPublicKeys.map(decPoint),
    ecdhPrivateKey: dec(input.ecdhPrivateKey),
    encryptionNonce: dec(input.encryptionNonce),
    authorityPublicKey: decPoint(input.authorityPublicKey),
  };
}
