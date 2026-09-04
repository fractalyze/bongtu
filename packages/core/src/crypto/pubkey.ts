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

import { sha256 } from "@noble/hashes/sha2.js";

import { P, A, D, isOnCurve, mod, modpow, inv } from "@bongtu/core/babyjub";
import type { Point, PointInput } from "@bongtu/core/babyjub";

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

  // Factor P-1 = Q * 2^S with Q odd (recursive form of the halving loop).
  const factor = (q: bigint, s: bigint): { q: bigint; s: bigint } =>
    (q & 1n) === 0n ? factor(q >> 1n, s + 1n) : { q, s };
  const { q: Q, s: S } = factor(P - 1n, 0n);

  // A fixed quadratic non-residue (search up from 2 — deterministic, no RNG).
  const nonResidue = (z: bigint): bigint => (legendre(z) === P - 1n ? z : nonResidue(z + 1n));
  const z = nonResidue(2n);

  // Least i in (0, M) with t^(2^i) == 1 — null once i reaches M (defensive;
  // legendre already screened non-residues out).
  const leastOrder = (tt: bigint, i: bigint, M: bigint): bigint | null => {
    const sq = mod(tt * tt);
    const ni = i + 1n;
    if (ni === M) return null;
    return sq === 1n ? ni : leastOrder(sq, ni, M);
  };
  // The Tonelli-Shanks descent: M strictly decreases, so depth <= S (~28 here).
  const descend = (M: bigint, c: bigint, t: bigint, R: bigint): bigint | null => {
    if (t === 1n) return R;
    const i = leastOrder(t, 0n, M);
    if (i === null) return null;
    const b = modpow(c, 1n << (M - i - 1n));
    const c2 = mod(b * b);
    return descend(i, c2, mod(t * c2), mod(R * b));
  };
  return descend(S, modpow(z, Q), modpow(n, Q), modpow(n, (Q + 1n) / 2n));
}

/**
 * Compress a BabyJubJub point to a 32-byte hex string ("0x" + 64 hex chars):
 * little-endian y with the top bit of the final byte carrying x's parity (x & 1).
 */
export function packPubkey(point: PointInput): string {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  const bytes = Uint8Array.from({ length: 32 }, (_, i) => Number((y >> BigInt(8 * i)) & 0xffn));
  if ((x & 1n) === 1n) bytes[31] |= 0x80; // sign bit = LSB of x
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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
  const bytes = Uint8Array.from({ length: 32 }, (_, i) => parseInt(h.slice(i * 2, i * 2 + 2), 16));

  const signBit = (bytes[31] & 0x80) >> 7; // parity of x
  bytes[31] &= 0x7f; // clear the sign bit before reading y
  const y = bytes.reduceRight<bigint>((acc, b) => (acc << 8n) | BigInt(b), 0n);
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

// ---------------------------------------------------------------------------
// base58check address format (the user-facing WIRE/DISPLAY encoding).
//
// Everything below the UI edge keeps the 0x-hex compressed pubkey; base58check
// exists only so what users see/copy/paste is compact, case-unambiguous
// (Bitcoin alphabet — no 0OIl) and TYPO-DETECTING: a 4-byte double-sha256
// checksum makes a mistyped character fail loudly instead of paying a stranger.
//
//   encodeAddress: 0x-hex -> base58( VERSION || payload(32) || sha256(sha256(VERSION||payload))[0..4] )
//   decodeAddress: base58check OR legacy 0x-hex -> canonical lowercase 0x-hex.
//                  This is the ONE normalization point every input edge routes through.

/**
 * Address version byte. 0x42 (ASCII 'B', for Bongtu) — with a 37-byte
 * version||payload||checksum string this pins every address to the visual
 * prefix "3" at a fixed 51 characters, and disambiguates bongtu addresses
 * from other base58check namespaces.
 */
export const ADDRESS_VERSION = 0x42;

// Bitcoin base58 alphabet: no 0 (zero), O, I, l — the visually ambiguous glyphs.
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX = new Map<string, bigint>([...B58_ALPHABET].map((c, i) => [c, BigInt(i)]));

function b58encode(bytes: Uint8Array): string {
  const n = bytes.reduce<bigint>((acc, b) => (acc << 8n) | BigInt(b), 0n);
  const digits = (v: bigint): string => (v === 0n ? "" : digits(v / 58n) + B58_ALPHABET[Number(v % 58n)]);
  // Leading zero bytes carry no big-integer weight — encode each as '1'.
  const firstNonZero = bytes.findIndex((b) => b !== 0);
  const leadingOnes = firstNonZero === -1 ? bytes.length : firstNonZero;
  return "1".repeat(leadingOnes) + digits(n);
}

function b58decode(s: string): Uint8Array {
  const n = [...s].reduce<bigint>((acc, c) => {
    const v = B58_INDEX.get(c);
    if (v === undefined) {
      throw new Error(`decodeAddress: invalid base58 character ${JSON.stringify(c)}`);
    }
    return acc * 58n + v;
  }, 0n);
  const toBytes = (v: bigint): number[] => (v === 0n ? [] : [...toBytes(v >> 8n), Number(v & 0xffn)]);
  const leading = /^1*/.exec(s)?.[0].length ?? 0;
  return new Uint8Array([...Array<number>(leading).fill(0), ...toBytes(n)]);
}

function checksum4(versionAndPayload: Uint8Array): Uint8Array {
  return sha256(sha256(versionAndPayload)).slice(0, 4);
}

// The legacy on-the-wire shape: 32-byte hex, 0x optional, case-insensitive —
// exactly what unpackPubkey has always accepted.
const HEX_ADDRESS_RE = /^(0x|0X)?[0-9a-fA-F]{64}$/;

/**
 * Encode a compressed bjj pubkey (0x-hex, as produced by packPubkey) as a
 * user-facing base58check address ("3…", 51 chars).
 */
export function encodeAddress(compressedHex: string): string {
  const v = compressedHex.trim();
  if (!HEX_ADDRESS_RE.test(v)) {
    throw new Error(`encodeAddress: expected 32-byte hex (64 chars), got ${JSON.stringify(compressedHex)}`);
  }
  const h = v.startsWith("0x") || v.startsWith("0X") ? v.slice(2) : v;
  const body = new Uint8Array(33);
  body[0] = ADDRESS_VERSION;
  for (const i of Array(32).keys()) body[i + 1] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  const full = new Uint8Array(37);
  full.set(body);
  full.set(checksum4(body), 33);
  return b58encode(full);
}

/**
 * Normalize ANY user-supplied address — base58check or legacy hex — to the
 * canonical internal form: lowercase 0x-prefixed 32-byte hex. Throws a distinct
 * error per failure mode (alphabet / length / checksum / version / off-curve),
 * so callers can surface "typo" separately from "not an address at all".
 */
export function decodeAddress(input: string): string {
  const v = input.trim();
  // Legacy hex short-circuits BEFORE base58: every 64-char hex string is taken
  // as hex (a base58 address is 51 chars, so the two shapes never collide).
  if (HEX_ADDRESS_RE.test(v)) {
    unpackPubkey(v); // curve-validate; throws its own descriptive error
    const h = v.startsWith("0x") || v.startsWith("0X") ? v.slice(2) : v;
    return "0x" + h.toLowerCase();
  }
  if (v === "") throw new Error("decodeAddress: empty address");
  const bytes = b58decode(v);
  if (bytes.length !== 37) {
    throw new Error(`decodeAddress: bad length (${bytes.length} bytes, expected 37)`);
  }
  const body = bytes.slice(0, 33);
  const check = checksum4(body);
  for (const i of Array(4).keys()) {
    if (check[i] !== bytes[33 + i]) throw new Error("decodeAddress: bad checksum");
  }
  if (body[0] !== ADDRESS_VERSION) {
    throw new Error(`decodeAddress: unknown address version 0x${body[0].toString(16).padStart(2, "0")}`);
  }
  const hex = Array.from(body.slice(1, 33), (b) => b.toString(16).padStart(2, "0")).join("");
  unpackPubkey(hex); // the payload must be a real compressed bjj pubkey
  return "0x" + hex;
}
