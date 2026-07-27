// PURE wallet-side witness assembly for the two small CPU circuits the public app
// proves in the browser: transfer (2-in / 2-out) and withdraw (2-in / 1-out), SPEC
// §4 / §7. Framework- and network-free so the exact code runs in the browser view
// AND the headless spend-witness gate. It imports the sdk crypto DIRECTLY, so every
// commitment / nullifier is byte-identical to what snarkjs proves and the contract
// verifies — the witness objects produced here are EXACTLY the circom `main` inputs
// deploy/e2e_orchestrator.ts assembles by hand, in ProvingRequest form (@bongtu/core/proving).
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
} from "@bongtu/core/note";
import { ml_kem768, kemSsToLimbs, kemHexToBytes, kemBytesToHex } from "@bongtu/core/kem";
import { ARBITER_KEM_PK } from "@bongtu/core/network";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { foldToRoot } from "@bongtu/core/imt";
import type { Point } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import type {
  TransferInput,
  WithdrawInput,
  ProvingRequest,
} from "@bongtu/core/proving";
import type { WalletIdentity } from "./derive.js";
import { DEFAULTS, H } from "../config.js";

// --- app-facing input shapes (all field elements as decimal strings) ------------

/** An unspent note the wallet owns, as surfaced by the balance view. The wallet is
 *  the owner, so the spending key is the derived identity — not carried per note. */
export interface WalletInputNote {
  value: string;
  salt: string;
  leafIndex: number;
}

/** What note selection picks from: the balance view's notes (a structural subset
 *  of the indexer's OwnerNote, so `/notes` results feed in directly). */
export interface SelectableNote {
  value: string;
  salt: string;
  leafIndex: number;
  spent: boolean;
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
  /** ML-KEM-768 shared-secret limbs (decimal) — the PQ half of the hybrid
   *  envelope key, a fresh encapsulation per tx (pq-envelope-design.md §5). */
  kemSs: [string, string];
  /** the matching 1088-byte encapsulation ciphertext, 0x-hex — the tx's
   *  `bytes kemCiphertext` calldata arg. */
  kemCiphertext: string;
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

// --- note selection + per-tx crypto ---------------------------------------------

/**
 * Pick which unspent notes fund a payment of `amount` — the wallet's coin
 * selection, PURE. Amount-aware largest-first cover with at most 2 notes (the
 * transfer/withdraw circuits take exactly 2 inputs, padding the second): if the
 * largest unspent note covers the amount it is spent alone; otherwise the two
 * largest are tried. Largest-first is optimal here — if ANY single note covers,
 * the largest does, and if ANY pair covers, the two largest do.
 *
 * Distinct failures so the UI can say the right thing:
 *   - no spendable notes at all (balance not loaded / everything spent);
 *   - "insufficient balance": the whole unspent total is below the amount;
 *   - "more than 2 notes": the balance suffices but no 1- or 2-note cover
 *     exists — the user must consolidate (e.g. two smaller spends) first.
 */
export function selectInputNotes(notes: readonly SelectableNote[], amount: string): WalletInputNote[] {
  let amt: bigint;
  try {
    amt = BigInt(amount);
  } catch {
    throw new Error(`amount must be a positive integer, got ${JSON.stringify(amount)}`);
  }
  if (amt <= 0n) throw new Error(`amount must be a positive integer, got ${amt}`);

  const unspent = [...notes]
    .filter((n) => !n.spent)
    .sort((a, b) => {
      const d = BigInt(b.value) - BigInt(a.value); // value descending…
      return d > 0n ? 1 : d < 0n ? -1 : a.leafIndex - b.leafIndex; // …then leafIndex for determinism
    });
  if (unspent.length === 0) throw new Error("no spendable notes — load your balance first");

  const pick = (n: SelectableNote): WalletInputNote => ({ value: n.value, salt: n.salt, leafIndex: n.leafIndex });
  const [first, second] = unspent;
  if (BigInt(first.value) >= amt) return [pick(first)];
  if (second && BigInt(first.value) + BigInt(second.value) >= amt) return [pick(first), pick(second)];

  const total = unspent.reduce((s, n) => s + BigInt(n.value), 0n);
  if (total < amt) {
    throw new Error(`insufficient balance: amount ${amt} exceeds unspent total ${total}`);
  }
  const pairTotal = BigInt(first.value) + BigInt(second!.value);
  throw new Error(
    `amount ${amt} needs more than 2 notes (largest two cover ${pairTotal}); ` +
      `a spend takes at most 2 input notes — consolidate or split the payment first`,
  );
}

/** A fresh field element (decimal string) per call — the injectable randomness
 *  behind `freshSpendCrypto` (the platform CSPRNG via `randField` below; a
 *  deterministic double in tests). */
export type RandField = () => string;

// Fresh per-tx field randomness, from the platform CSPRNG. A shared ephemeral ECDH key
// + nonce across outputs of ONE tx is fine; reuse ACROSS txs is a two-time pad, so both
// spend and deposit draw fresh values every action.
export function randField(): string {
  const b = new Uint8Array(31); // < 2^248, safely under the field prime
  crypto.getRandomValues(b);
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return (x === 0n ? 1n : x).toString();
}

/** One ML-KEM encapsulation result in wire form: witness limbs + tx ct. */
export interface KemMaterial {
  kemSs: [string, string];
  kemCiphertext: string;
}

/** The injectable KEM draw behind fresh{Spend,Deposit}Crypto — real
 *  encapsulation in the browser, a deterministic double in tests. */
export type KemDrawFn = () => KemMaterial;

/**
 * Fresh ML-KEM-768 encapsulation against the institutional arbiter key
 * (ARBITER_KEM_PK — the pool stores its keccak256 per epoch). One encapsulation
 * PER TX: reusing a ct across ops collapses the PQ compartment
 * (pq-envelope-design.md §6), so this is drawn alongside the ECDH ephemeral in
 * every fresh crypto bundle. noble's encapsulate uses the platform CSPRNG.
 */
export function freshKemMaterial(): KemMaterial {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK));
  const [l0, l1] = kemSsToLimbs(sharedSecret);
  return { kemSs: [l0.toString(), l1.toString()], kemCiphertext: kemBytesToHex(cipherText) };
}

/**
 * Clamp a fresh field draw to a valid Poseidon-encryption nonce. Every circuit's
 * `SymmetricEncrypt` constrains `nonce < 2^128` (zeto encrypt.circom — the nonce
 * shares a Poseidon state slot with `messageLength * 2^128`), so a full-width
 * field draw fails witness generation with "Assert Failed … SymmetricEncrypt".
 * Masking to the low 128 bits keeps the draw uniform.
 */
export function toEncryptionNonce(fieldDraw: string): string {
  return (BigInt(fieldDraw) & ((1n << 128n) - 1n)).toString();
}

/**
 * Draw the fresh per-tx crypto material for one spend. Every draw is a NEW field
 * element from `rand`: sharing the ephemeral ECDH key + nonce across outputs of
 * ONE tx is fine, but reuse ACROSS txs is a two-time pad — so callers draw a
 * whole fresh SpendCrypto per spend. The authority target is the pool's stored
 * arbiter PUBLIC key (§6b v2): the contract injects the same key from storage
 * before verifying, so a different target fails the proof. `drawKem` adds the
 * fresh per-tx ML-KEM encapsulation (hybrid envelope, injectable for tests).
 */
export function freshSpendCrypto(rand: RandField, drawKem: KemDrawFn = freshKemMaterial): SpendCrypto {
  const kem = drawKem();
  return {
    ecdhPrivateKey: rand(),
    encryptionNonce: toEncryptionNonce(rand()),
    authorityPubKey: DEFAULTS.arbiterPubKey,
    kemSs: kem.kemSs,
    kemCiphertext: kem.kemCiphertext,
    changeSalt: rand(),
    padSalt: rand(),
    payeeSalt: rand(),
  };
}

// --- helpers -------------------------------------------------------------------

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
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
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
