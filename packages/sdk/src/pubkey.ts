// BabyJubJub public-key point compression (SPEC §6b v2 note-owner identifier).
//
// A note owner is identified by its BabyJubJub public key. On the wire (the
// indexer `/notes?owner=` param, wallet URLs, receipts) we carry the key as ONE
// 32-byte hex string rather than a raw "x,y" decimal pair, using the standard
// twisted-Edwards compression: the point is (mostly) determined by y, and the
// single ambiguous bit — which of the two x roots — is stored in the top bit of
// the little-endian y encoding.
//
//   packPubkey([x,y])  -> "0x" + 32-byte LE(y), with bit 255 (top bit of the last
//                         byte) set to the LSB of x (x & 1) — the RFC-8032 sign
//                         convention (parity of x), NOT circomlib's x>(p-1)/2.
//   unpackPubkey(hex)  -> recover y (clear the sign bit), solve the curve equation
//                         for x^2, take the modular sqrt, then pick the root whose
//                         parity matches the stored sign bit. Validated on-curve.
//
// Field sqrt is Tonelli-Shanks: the base field prime p ≡ 1 (mod 4) (in fact 2^28
// divides p-1), so the (p+1)/4 shortcut does not apply.

import { P, A, D, isOnCurve, mod, modpow, inv } from "./babyjub.js";
import type { Point, PointInput } from "./babyjub.js";

// Legendre symbol: 1 if a is a nonzero quadratic residue, P-1 if a non-residue.
function legendre(a: bigint): bigint {
  return modpow(a, (P - 1n) / 2n);
}

// Tonelli-Shanks modular square root. Returns an r with r*r == n (mod P), or null
// when n is a quadratic non-residue (no such r exists — an off-curve y).
export function sqrtMod(n: bigint): bigint | null {
  n = mod(n);
  if (n === 0n) return 0n;
  if (legendre(n) !== 1n) return null;

  // Factor P-1 = Q * 2^S with Q odd.
  let Q = P - 1n;
  let S = 0n;
  while ((Q & 1n) === 0n) {
    Q >>= 1n;
    S += 1n;
  }

  // A fixed quadratic non-residue (search up from 2 — deterministic, no RNG).
  let z = 2n;
  while (legendre(z) !== P - 1n) z += 1n;

  let M = S;
  let c = modpow(z, Q);
  let t = modpow(n, Q);
  let R = modpow(n, (Q + 1n) / 2n);
  while (t !== 1n) {
    // Least i in (0, M) with t^(2^i) == 1.
    let i = 0n;
    let tt = t;
    while (tt !== 1n) {
      tt = mod(tt * tt);
      i += 1n;
      if (i === M) return null; // not a residue (defensive; legendre already screened)
    }
    const b = modpow(c, 1n << (M - i - 1n));
    M = i;
    c = mod(b * b);
    t = mod(t * c);
    R = mod(R * b);
  }
  return R;
}

/**
 * Compress a BabyJubJub point to a 32-byte hex string ("0x" + 64 hex chars):
 * little-endian y with the top bit of the final byte carrying x's parity (x & 1).
 */
export function packPubkey(point: PointInput): string {
  const x = BigInt(point[0]);
  let y = BigInt(point[1]);
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(y & 0xffn);
    y >>= 8n;
  }
  if ((x & 1n) === 1n) bytes[31] |= 0x80; // sign bit = LSB of x
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return "0x" + hex;
}

/**
 * Decompress a 32-byte hex string back to [x, y], recovering x from the curve
 * equation and the stored sign bit. Throws on malformed input (bad length / hex),
 * a y with no valid x (off-curve), or a recovered point failing the curve check.
 */
export function unpackPubkey(hex: string): Point {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(h)) {
    throw new Error(`unpackPubkey: expected 32-byte hex (64 chars), got ${JSON.stringify(hex)}`);
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);

  const signBit = (bytes[31] & 0x80) >> 7; // parity of x
  bytes[31] &= 0x7f; // clear the sign bit before reading y
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  if (y >= P) throw new Error("unpackPubkey: y out of field range");

  // a*x^2 + y^2 = 1 + d*x^2*y^2  ->  x^2 * (a - d*y^2) = 1 - y^2
  const y2 = mod(y * y);
  const num = mod(1n - y2);
  const den = mod(A - mod(D * y2));
  const x2 = mod(num * inv(den));
  const root = sqrtMod(x2);
  if (root === null) throw new Error("unpackPubkey: y is not on the curve (x^2 is a non-residue)");

  // Pick the root whose parity matches the stored sign bit.
  const x = (root & 1n) === BigInt(signBit) ? root : mod(P - root);
  const point: Point = [x, y];
  if (!isOnCurve(point)) throw new Error("unpackPubkey: recovered point is not on the curve");
  return point;
}
