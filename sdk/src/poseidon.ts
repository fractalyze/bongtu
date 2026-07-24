// Poseidon-v1 over BN254 (circomlib-compatible), backed by poseidon-lite (MIT).
//
// This is the ONE hash the whole system must agree on: the circom circuits use
// circomlib's Poseidon-v1, the on-chain Poseidon contract is generated from the
// same circomlib constants, and this module is the JS oracle. poseidon-lite
// implements exactly those constants, so poseidon2(1n, 2n) equals the reference
//   7853200120776062878684798364095072458815029376092732009249414926327459813530
// (the parity gate). If that ever drifts, swap the hash dep — do NOT hand-tune.
//
// All inputs and outputs are field elements as native BigInt.

import {
  poseidon1,
  poseidon2 as _poseidon2,
  poseidon3,
  poseidon4,
  poseidon5,
  poseidon6,
  poseidon7,
  poseidon8,
  poseidon9,
  poseidon10,
  poseidon11,
  poseidon12,
  poseidon13,
  poseidon14,
  poseidon15,
  poseidon16,
} from "poseidon-lite";

// A field element in a form the hash accepts (coerced to BigInt before hashing).
export type FieldInput = bigint | number | string;

// The fixed-arity signature every poseidon-lite hash shares.
type PoseidonFn = (input: FieldInput[]) => bigint;

// BN254 (alt_bn128) scalar field prime — the field every element lives in.
// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
export const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// poseidon-lite exposes one fixed-arity function per input count.
const BY_ARITY: Record<number, PoseidonFn> = {
  1: poseidon1,
  2: _poseidon2,
  3: poseidon3,
  4: poseidon4,
  5: poseidon5,
  6: poseidon6,
  7: poseidon7,
  8: poseidon8,
  9: poseidon9,
  10: poseidon10,
  11: poseidon11,
  12: poseidon12,
  13: poseidon13,
  14: poseidon14,
  15: poseidon15,
  16: poseidon16,
};

// The 2-input hash — the tree's node combiner and the parity gate.
export function poseidon2(a: FieldInput, b: FieldInput): bigint {
  return _poseidon2([BigInt(a), BigInt(b)]);
}

// Variable-arity Poseidon over an array of field elements (arity 1..16).
// Used for commitment = poseidonN([value, salt, ownerPubX, ownerPubY]) and
// nullifier = poseidonN([value, salt, ownerFormattedPrivKey]).
export function poseidonN(arr: FieldInput[]): bigint {
  const fn = BY_ARITY[arr.length];
  if (!fn) {
    throw new Error(`poseidonN: unsupported arity ${arr.length} (expected 1..16)`);
  }
  return fn(arr.map((x) => BigInt(x)));
}
