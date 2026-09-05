// ops/spend/crypto.ts — fresh per-tx randomness + KEM draws (split from spend.ts).

import { ml_kem768, kemSsToLimbs, kemHexToBytes, kemBytesToHex } from "@bongtu/core/kem";
import { ARBITER_KEM_PK, ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y } from "@bongtu/core/network";
import { MAX_INPUT_PADS, MAX_OUTPUT_PADS, type SpendCrypto } from "./plan.js";

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
  const x = b.reduce<bigint>((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
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
 *
 * The pad salts are drawn for the WIDEST arity (transfer10x2) on every spend, so one
 * bundle serves whichever circuit the auto-pick lands on — a 2×2 spend simply uses
 * the first of them. Drawing 21 field elements is microseconds next to the proof.
 */
export function freshSpendCrypto(rand: RandField, drawKem: KemDrawFn = freshKemMaterial): SpendCrypto {
  const kem = drawKem();
  return {
    ecdhPrivateKey: rand(),
    encryptionNonce: toEncryptionNonce(rand()),
    authorityPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y],
    kemSs: kem.kemSs,
    kemCiphertext: kem.kemCiphertext,
    changeSalt: rand(),
    padSalts: Array.from({ length: MAX_INPUT_PADS }, () => rand()),
    payeeSalt: rand(),
    outputPadSalts: Array.from({ length: MAX_OUTPUT_PADS }, () => rand()),
  };
}
