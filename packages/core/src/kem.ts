// Hybrid (ECDH || ML-KEM-768) authority-envelope key derivation — the TS side
// of .dev/pq-envelope-design.md §2. The four circuits derive the SAME values
// in-circuit; drift here breaks arbiter decryption of live envelopes, so the
// tag literals below are FROZEN (sha256(ASCII) mod r, computed 2026-07-27) and
// must stay byte-equal to the circuit literals.
//
//   kemSs[0] = LE-uint128(ss[0..16])      // ss = the 32-byte ML-KEM shared secret
//   kemSs[1] = LE-uint128(ss[16..32])     // two exact 128-bit limbs, no reduction, no bias
//   hybridKey[i] = Poseidon(5)([TAG_Ki, ecdh.x, ecdh.y, kemSs[0], kemSs[1]])
//   kemBinding   = Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]])
//
// Key derivation (arity 5) and binding (arity 3) are separated by both tag and
// arity. ML-KEM-768 itself comes from @noble/post-quantum (re-exported here so
// @bongtu/core is the ONE owner of the dependency; ct 1088 B, ek 1184 B).
//
// Browser-safe: no node builtins (wallet-web/payroll-web encapsulate in-page).

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import type { FieldInput, PointInput } from "@bongtu/core/babyjub";
import { poseidonN } from "@bongtu/core/poseidon";

export { ml_kem768 };

/** ML-KEM-768 wire sizes (FIPS 203). */
export const KEM_CIPHERTEXT_BYTES = 1088;
export const KEM_PUBLIC_KEY_BYTES = 1184;
export const KEM_SHARED_SECRET_BYTES = 32;
export const KEM_SECRET_KEY_BYTES = 2400;

// FIPS 203 §6.1: dk = dk_PKE (384·k = 1152 B) ‖ ek (1184 B) ‖ H(ek) (32 B) ‖ z (32 B).
const KEM_SECRET_EK_OFFSET = 1152;

/**
 * The encapsulation key embedded in an ML-KEM-768 decapsulation key. Lets a
 * key holder prove WHICH pk its secret matches without a decapsulation
 * round-trip — decapsulating with a wrong-but-well-formed dk does not throw
 * (implicit rejection yields pseudorandom ss), so a mismatched key would
 * otherwise surface only as binding-mismatch alarms on every honest op.
 */
export function kemPkFromSecret(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== KEM_SECRET_KEY_BYTES) {
    throw new Error(
      `kemPkFromSecret: ML-KEM-768 decapsulation key is ${KEM_SECRET_KEY_BYTES} bytes, got ${secretKey.length}`,
    );
  }
  return secretKey.slice(KEM_SECRET_EK_OFFSET, KEM_SECRET_EK_OFFSET + KEM_PUBLIC_KEY_BYTES);
}

// Domain-separation tags: sha256(ASCII) mod r (BN254 scalar field), frozen.
//   TAG_K0   = sha256("bongtu/pq-envelope/v1/key0")    mod r
//   TAG_K1   = sha256("bongtu/pq-envelope/v1/key1")    mod r
//   TAG_BIND = sha256("bongtu/pq-envelope/v1/binding") mod r
export const TAG_K0 =
  10398998902367040515226727887904115149378422647845688990538198988921570667720n;
export const TAG_K1 =
  7025394518961265764175593663800963341053996587382265036146196548941915994055n;
export const TAG_BIND =
  5518019128667894418081277213291049553290157756968653594844689494754896839788n;

/** Hex ("0x"-optional) -> bytes, for KEM wire material (pk 1184 B / ct 1088 B /
 *  dk 2400 B). Browser-safe (no node Buffer) — the wallet decodes ARBITER_KEM_PK
 *  with this before encapsulating. */
export function kemHexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) {
    throw new Error(`kemHexToBytes: not an even-length hex string (${h.length} chars)`);
  }
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16));
}

/** Bytes -> "0x…" hex — the tx-calldata form of a kemCiphertext. */
export function kemBytesToHex(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Split the 32-byte ML-KEM shared secret into two little-endian 128-bit limbs
 *  (< 2^128 < r each, so the mapping is uniform — no modular bias). */
export function kemSsToLimbs(ss: Uint8Array): [bigint, bigint] {
  if (ss.length !== KEM_SHARED_SECRET_BYTES) {
    throw new Error(`kemSsToLimbs: expected ${KEM_SHARED_SECRET_BYTES} bytes, got ${ss.length}`);
  }
  const le = (bytes: Uint8Array): bigint =>
    bytes.reduceRight<bigint>((v, b) => (v << 8n) | BigInt(b), 0n);
  return [le(ss.subarray(0, 16)), le(ss.subarray(16, 32))];
}

/** The hybrid envelope key: folds the classical ECDH point and the ML-KEM limbs
 *  through tagged Poseidon(5) — equals the circuits' `hybridKey[2]`, and is the
 *  `key[2]` for poseidonEncrypt/poseidonDecrypt of the authority envelope. */
export function hybridEnvelopeKey(
  ecdhShared: PointInput,
  kemSs: [FieldInput, FieldInput],
): [bigint, bigint] {
  const tail = [BigInt(ecdhShared[0]), BigInt(ecdhShared[1]), BigInt(kemSs[0]), BigInt(kemSs[1])];
  return [poseidonN([TAG_K0, ...tail]), poseidonN([TAG_K1, ...tail])];
}

/** The public binding the circuits output: Poseidon(3)([TAG_BIND, limbs]). The
 *  arbiter recomputes it from Decaps(ct) — a mismatch is a first-class alarm
 *  (junk-wrapped KEM ct), per .dev/pq-envelope-design.md §2/§5. */
export function kemBindingOf(kemSs: [FieldInput, FieldInput]): bigint {
  return poseidonN([TAG_BIND, BigInt(kemSs[0]), BigInt(kemSs[1])]);
}
