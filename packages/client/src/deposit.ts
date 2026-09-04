// PURE wallet-side witness assembly for the deposit/shield circuit (SPEC §4, 0-in /
// 2-out mint). Modeled on spend.ts: framework- and network-free so the exact code runs
// in the browser view AND a headless gate, importing the sdk crypto DIRECTLY so every
// output commitment is byte-identical to what snarkjs proves and the contract verifies.
// The witness object produced here is EXACTLY the circom `main` input the
// deploy/gates/e2e_orchestrator.ts deposit section assembles by hand, in ProvingRequest form.
//
// A deposit mints TWO outputs — note(V) at index 0 and note(0) at index 1 — BOTH owned
// by the depositor. Deposit has NO membership and NO nullifiers, and it publishes no
// per-recipient ciphertext (a single authority/arbiter envelope over both outputs), so
// the two outputs sharing one owner is harmless (no two-time-pad, no assertDistinct).
// note(0) is a REAL commitment of value 0 with a random salt+owner — non-zero, so it
// passes the contract's ZeroOutputCommitment check.
//
// What it does NOT do (SPEC §6 boundary): it does not prove (browser snarkjs, prove.ts),
// approve the ERC-20, or send the tx (connection.ts). It stops at "a valid deposit
// ProvingRequest", ready to prove and submit.

import { commitment } from "@bongtu/core/note";
import { ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y } from "@bongtu/core/network";
import type { Point } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import type { DepositInput, ProvingRequest } from "@bongtu/core/proving";
import type { WalletIdentity } from "@bongtu/client/derive";
import { toEncryptionNonce, freshKemMaterial, type KemDrawFn } from "@bongtu/client/spend";

/** Fresh per-tx crypto material for one deposit. `ecdhPrivateKey`/`encryptionNonce`
 *  must never be reused across txs (a shared ephemeral key + nonce is a two-time pad);
 *  `salt0`/`salt1` are the fresh salts for note(V) and note(0). `authorityPubKey` is NOT
 *  drawn — it is the pool's fixed stored arbiter PUBLIC key (§6b v2), the envelope target
 *  the contract injects from storage before verifying, so a different target fails. */
export interface DepositCrypto {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** salt for output 0 = note(V). */
  salt0: string;
  /** salt for output 1 = note(0). */
  salt1: string;
  /** the pool's stored arbiter PUBLIC key — the authority envelope target. */
  authorityPubKey: [string, string];
  /** ML-KEM-768 shared-secret limbs (decimal) — the PQ half of the hybrid
   *  envelope key, a fresh encapsulation per tx (pq-envelope-design.md §5). */
  kemSs: [string, string];
  /** the matching 1088-byte encapsulation ciphertext, 0x-hex (tx calldata). */
  kemCiphertext: string;
}

export interface DepositMeta {
  /** [note(V), note(0)] commitments as decimal strings. */
  outputCommitments: string[];
  /** [V, 0] as decimal strings. */
  outputValues: string[];
  /** the deposited value V (== outputValues[0], == pub[0] on-chain). */
  amount: string;
}

export interface DepositResult {
  request: Extract<ProvingRequest, { circuit: "deposit" }>;
  meta: DepositMeta;
}

/** A fresh field element (decimal string) per call — the injectable randomness behind
 *  `freshDepositCrypto` (browser CSPRNG in the flow; deterministic in tests). */
export type RandField = () => string;

/**
 * Draw the fresh per-tx crypto material for one deposit. Exactly FOUR draws from
 * `rand` — ecdhPrivateKey, encryptionNonce, salt0, salt1 — since reusing an ephemeral
 * ECDH key + nonce across txs is a two-time pad; plus ONE ML-KEM encapsulation from
 * `drawKem` (fresh per tx — ct reuse collapses the PQ compartment, design doc §6).
 * `authorityPubKey` is NOT drawn: it is the pool's fixed stored arbiter PUBLIC key
 * (the contract injects the same key before verifying, so a different target fails
 * the proof).
 */
export function freshDepositCrypto(rand: RandField, drawKem: KemDrawFn = freshKemMaterial): DepositCrypto {
  const kem = drawKem();
  return {
    ecdhPrivateKey: rand(),
    // clamped: SymmetricEncrypt constrains nonce < 2^128 (see toEncryptionNonce)
    encryptionNonce: toEncryptionNonce(rand()),
    salt0: rand(),
    salt1: rand(),
    authorityPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y],
    kemSs: kem.kemSs,
    kemCiphertext: kem.kemCiphertext,
  };
}

/**
 * Cheap PURE precheck the deposit flow runs right after reading token state: a deposit
 * of `V` raw units cannot succeed if it exceeds the depositor's public kKRW `balance`
 * (the pool pulls exactly V via safeTransferFrom, which would revert). Throwing here —
 * BEFORE the approve tx and the multi-second proof — mirrors spend.ts selectInputNotes
 * rejecting an over-spend, and saves a wasted approve + proof on a doomed deposit.
 */
export function assertDepositAffordable(V: bigint, balance: bigint): void {
  if (V > balance) {
    throw new Error(`insufficient kKRW balance: deposit ${V} exceeds balance ${balance}`);
  }
}

/**
 * Assemble a deposit ProvingRequest: mint `amount` (V) into the pool as note(V) +
 * note(0), BOTH owned by the wallet. Value is exactly [V, 0] (sum == V). The two output
 * commitments are recomputed with the sdk `commitment()` — byte-identical to the
 * circuit / contract. The authority envelope targets `crypto.authorityPubKey` (the
 * pool's stored arbiter key).
 *
 * Throws on a non-positive amount.
 */
export function buildDepositRequest(
  identity: WalletIdentity,
  amount: string,
  crypto: DepositCrypto,
): DepositResult {
  const self = identity.keypair;
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);

  const owner = self.publicKey;
  const salt0 = BigInt(crypto.salt0);
  const salt1 = BigInt(crypto.salt1);
  const outputValues = [V, 0n];
  const outputSalts = [salt0, salt1];
  const outputOwnerPublicKeys: Point[] = [owner, owner];
  const outputCommitments = [
    commitment(V, salt0, owner), // note(V)
    commitment(0n, salt1, owner), // note(0) — real commitment of value 0, non-zero
  ];

  const inputBig: DepositInput = {
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "deposit", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: {
      outputCommitments: outputCommitments.map((x) => x.toString()),
      outputValues: outputValues.map((x) => x.toString()),
      amount: V.toString(),
    },
  };
}
