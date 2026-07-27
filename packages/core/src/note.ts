// Note / key / encryption machinery for assembling circuit witnesses.
//
// Mirrors the semantics of zeto zkp/js/lib/util.js (Poseidon-sponge symmetric
// encryption via ECDH) but is a self-contained ESM reference: M0 verifies via
// snarkjs, not the on-chain contract, so we only need the values that make the
// circom witness satisfiable and let U3/U4 trial-decrypt.
//
//   commitment = poseidon4([value, salt, ownerPubX, ownerPubY])
//   nullifier  = poseidon3([value, salt, ownerFormattedPrivKey])
//   ciphertext = Poseidon-sponge(msg) keyed by ECDH(ephemeralPriv, ownerPub)
//
// No Math.random anywhere: salts / nonces / test scalars are derived from an
// index so fixtures are reproducible and the workflow env is satisfied.

import { poseidon4 } from "poseidon-lite";
import { poseidonN, FIELD_PRIME } from "./poseidon.js";
import { Base8, mulPointEscalar } from "./babyjub.js";
import type { FieldInput, Point, PointInput } from "./babyjub.js";

// poseidon-lite's fixed-arity fns return a length-`nOuts` ARRAY when nOuts > 1
// (its .d.ts only types the nOuts=1 single-bigint case). The Poseidon sponge
// runs the full 4-element permutation, so use the accurate array signature.
const poseidonPerm = poseidon4 as unknown as (input: bigint[], nOuts: number) => bigint[];

export const F = FIELD_PRIME;
const TWO128 = 340282366920938463463374607431768211456n; // 2^128

// A derived BabyJubJub keypair: the formatted private scalar + its public point.
export interface Keypair {
  formattedPrivateKey: bigint;
  publicKey: Point;
}

// Derive a BabyJubJub keypair from a fixed scalar. The scalar IS the
// "formatted private key" the circuit consumes directly (BabyPbk / nullifier
// preimage), so callers must pass an already-reduced scalar (< subgroup order).
export function deriveKeypair(scalar: FieldInput): Keypair {
  const sk = BigInt(scalar);
  if (sk <= 0n || sk >= F) {
    throw new Error(`deriveKeypair: scalar out of range: ${sk}`);
  }
  const publicKey = mulPointEscalar(Base8, sk);
  return { formattedPrivateKey: sk, publicKey };
}

export function commitment(value: FieldInput, salt: FieldInput, publicKey: PointInput): bigint {
  return poseidonN([
    BigInt(value),
    BigInt(salt),
    BigInt(publicKey[0]),
    BigInt(publicKey[1]),
  ]);
}

export function nullifier(value: FieldInput, salt: FieldInput, formattedPrivateKey: FieldInput): bigint {
  return poseidonN([BigInt(value), BigInt(salt), BigInt(formattedPrivateKey)]);
}

// ECDH shared secret point = privScalar * pubPoint (== the circuit's Ecdh()).
export function ecdhSharedSecret(privScalar: FieldInput, pubPoint: PointInput): Point {
  return mulPointEscalar(
    [BigInt(pubPoint[0]), BigInt(pubPoint[1])],
    BigInt(privScalar),
  );
}

function addMod(a: FieldInput, b: FieldInput): bigint {
  let r = ((BigInt(a) + F) % F) + BigInt(b);
  r %= F;
  while (r < 0n) r += F;
  return r;
}

// Poseidon-sponge symmetric encryption — byte-compatible with encrypt.circom's
// SymmetricEncrypt and zeto's poseidonEncrypt. `key` is the 2-coord ECDH point.
export function poseidonEncrypt(msg: FieldInput[], key: PointInput, nonce: FieldInput): bigint[] {
  const message = msg.map((m) => BigInt(m));
  while (message.length % 3 > 0) message.push(0n);

  let state: bigint[] = [0n, BigInt(key[0]), BigInt(key[1]), BigInt(nonce) + BigInt(msg.length) * TWO128];
  const ciphertext: bigint[] = [];
  const n = Math.floor(message.length / 3);
  for (let i = 0; i < n; i += 1) {
    state = poseidonPerm(state, 4);
    state[1] = addMod(message[i * 3], state[1]);
    state[2] = addMod(message[i * 3 + 1], state[2]);
    state[3] = addMod(message[i * 3 + 2], state[3]);
    ciphertext.push(state[1], state[2], state[3]);
  }
  state = poseidonPerm(state, 4);
  ciphertext.push(state[1]);
  return ciphertext;
}

export function poseidonDecrypt(ciphertext: FieldInput[], key: PointInput, nonce: FieldInput, length: number): bigint[] {
  let state: bigint[] = [0n, BigInt(key[0]), BigInt(key[1]), BigInt(nonce) + BigInt(length) * TWO128];
  const message: bigint[] = [];
  const n = Math.floor(ciphertext.length / 3);
  for (let i = 0; i < n; i += 1) {
    state = poseidonPerm(state, 4);
    message.push(addMod(ciphertext[i * 3], -state[1]));
    message.push(addMod(ciphertext[i * 3 + 1], -state[2]));
    message.push(addMod(ciphertext[i * 3 + 2], -state[3]));
    state[1] = BigInt(ciphertext[i * 3]);
    state[2] = BigInt(ciphertext[i * 3 + 1]);
    state[3] = BigInt(ciphertext[i * 3 + 2]);
  }
  return message.slice(0, length);
}

// SPEC §4 / §11-8 two-time-pad guard for the SHARED-nonce encryptors: all
// outputs of a disburse batch share ONE ephemeral key + ONE encryptionNonce, so
// two outputs to the same owner pubkey leak c1 - c2 = m1 - m2. The prover MUST
// reject duplicate output owner pubkeys there. TRANSFER is exempt since U-X3:
// its circuit derives a per-output receiver nonce (encryptionNonce + i, the
// §11-8 v1.1 structural fix), so a self-send no longer reuses a keystream and
// spend.ts deliberately does NOT call this for its 2 outputs.
export function assertDistinctOwnerPubkeys(publicKeys: PointInput[]): void {
  const seen = new Set<string>();
  for (const pk of publicKeys) {
    const key = `${BigInt(pk[0])},${BigInt(pk[1])}`;
    if (seen.has(key)) {
      throw new Error(
        `duplicate output owner pubkey (${key}): all outputs share one ephemeral ` +
          "key + nonce, so a repeated recipient leaks value/salt via a two-time pad " +
          "(SPEC §4 / §11-8). Reject before proving.",
      );
    }
    seen.add(key);
  }
}
