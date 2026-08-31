// Stealth-address derivation for pool-edge payments (withdraw destinations now,
// portal deposits later): a DKSAP-style dual-key scheme whose ECDH half runs on
// BabyJubJub and whose spend half runs on secp256k1.
//
// Why two curves. The one-time destination must be a plain Ethereum EOA, so the
// spendable key is necessarily secp256k1. The view half stays on BabyJubJub so
// (a) it reuses this package's curve + packing primitives and the wallet's
// existing signature-derived key story, and (b) the shared-secret computation
// matches the circuits' `Ecdh()` gadget, keeping the door open to proving
// "this withdraw destination was derived from the disclosed owner" in-circuit.
// A cross-curve scheme is REQUIRED, not a convenience: a BabyJubJub spend key
// cannot control an EOA, and a secp view key cannot be checked by a bn128
// Groth16 circuit.
//
// Scheme (sender / recipient views of the same algebra):
//
//   meta      viewPriv v ∈ [1,L)  viewPub  V = v·Base8      (BabyJubJub)
//             spendPriv s ∈ [1,N) spendPub K = s·G          (secp256k1)
//   sender    ephemeral r ∈ [1,L), R = r·Base8, S = r·V
//   both      h = keccak256("bongtu/stealth-v1" ‖ le32(S.x) ‖ le32(S.y))
//             viewTag = h[0],  t = int_be(h) mod N          (tweak)
//   address   P = K + t·G,  addr = keccak256(P_xy)[12..]
//   scan      S = v·R  → same h, so the recipient reproduces addr with the
//             VIEW key alone (detection without spend authority)
//   spend     p = (s + t) mod N  →  p·G == P  (only the s-holder can form p)
//
// The tweak must add to the spend KEY, not replace it: t is computable by
// anyone holding S (the sender included), so an address of the form t·G alone
// would be sender-spendable. Unlinkability of addr from (V, K, R) is exactly
// DDH on BabyJubJub — a third party without v or r cannot form S.
//
// No RNG is used at module scope and every function is pure; the one entropy
// helper (randomEphemeralScalar) draws from WebCrypto so it works in both the
// browser wallet and node, and callers in deterministic contexts pass their
// own scalar instead.

import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import { Base8, mulPointEscalar, SUBGROUP_ORDER } from "./babyjub.js";
import type { FieldInput, Point } from "./babyjub.js";
import { ecdhSharedSecret } from "./note.js";
import { packPubkey, unpackPubkey } from "./pubkey.js";

// secp256k1 group order. Hardcoded (like babyjub.ts's curve constants) and
// pinned against the library in the test suite ((N-1)·G + G == O).
export const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

const SecpPoint = secp256k1.Point;

// Domain tag hashed into every shared-secret digest: binds derived addresses
// to this scheme so the same meta keys can never collide with another
// protocol's derivation over the same curve points.
const DOMAIN_TAG = new TextEncoder().encode("bongtu/stealth-v1");

/** The public half a recipient registers: everything a sender needs. */
export interface StealthMetaAddress {
  /** compressed BabyJubJub view pubkey ("0x" + 32-byte hex, packPubkey form). */
  viewPub: string;
  /** compressed secp256k1 spend pubkey ("0x" + 33-byte hex). */
  spendPub: string;
}

/** A recipient's full stealth identity: both scalars plus the public half. */
export interface StealthKeys {
  viewPriv: bigint;
  spendPriv: bigint;
  meta: StealthMetaAddress;
}

/** What a sender produces: the announcement (R, viewTag) plus the destination. */
export interface StealthDerivation {
  /** compressed BabyJubJub ephemeral pubkey R — the on-announcement value. */
  ephemeralPub: string;
  /** first byte of the shared-secret digest — cheap scan pre-filter. */
  viewTag: number;
  /** the one-time EOA ("0x" + 20-byte hex, lowercase). */
  address: string;
}

function checkScalarRange(name: string, value: bigint, order: bigint): bigint {
  if (value <= 0n || value >= order) {
    throw new Error(`stealth: ${name} out of range [1, order)`);
  }
  return value;
}

/** Assemble a stealth identity from its two private scalars (range-checked). */
export function stealthKeysFromScalars(
  viewPriv: FieldInput,
  spendPriv: FieldInput,
): StealthKeys {
  const v = checkScalarRange("viewPriv", BigInt(viewPriv), SUBGROUP_ORDER);
  const s = checkScalarRange("spendPriv", BigInt(spendPriv), SECP256K1_ORDER);
  return {
    viewPriv: v,
    spendPriv: s,
    meta: {
      viewPub: packPubkey(mulPointEscalar(Base8, v)),
      spendPub: "0x" + bytesToHex(SecpPoint.BASE.multiply(s).toBytes(true)),
    },
  };
}

// 32-byte little-endian field-element encoding — same byte order packPubkey
// uses, so the digest layout follows the package's one wire convention.
function le32(x: bigint): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => Number((x >> BigInt(8 * i)) & 0xffn));
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  return bytes.reduce<bigint>((v, b) => (v << 8n) | BigInt(b), 0n);
}

// Shared tail of derive/scan/recover: shared secret point -> (viewTag, tweak).
function sharedSecretDigest(shared: Point): { viewTag: number; tweak: bigint } {
  const h = keccak_256(concatBytes(DOMAIN_TAG, le32(shared[0]), le32(shared[1])));
  const tweak = bytesToBigIntBE(h) % SECP256K1_ORDER;
  if (tweak === 0n) {
    // Unreachable in practice (probability ~2^-256); refuse rather than emit
    // an address the sender could spend (P would equal K exactly).
    throw new Error("stealth: degenerate zero tweak");
  }
  return { viewTag: h[0], tweak };
}

function addressFromPoint(p: InstanceType<typeof SecpPoint>): string {
  if (p.is0()) {
    throw new Error("stealth: degenerate infinity point");
  }
  const uncompressed = p.toBytes(false); // 0x04 ‖ x ‖ y
  return "0x" + bytesToHex(keccak_256(uncompressed.subarray(1)).subarray(12));
}

function parseSpendPub(spendPub: string): InstanceType<typeof SecpPoint> {
  const h = spendPub.startsWith("0x") || spendPub.startsWith("0X")
    ? spendPub.slice(2)
    : spendPub;
  return SecpPoint.fromBytes(hexToBytes(h)); // validates on-curve
}

function tweakToAddress(
  spendPubPoint: InstanceType<typeof SecpPoint>,
  shared: Point,
): { viewTag: number; tweak: bigint; address: string } {
  const { viewTag, tweak } = sharedSecretDigest(shared);
  const address = addressFromPoint(
    spendPubPoint.add(SecpPoint.BASE.multiply(tweak)),
  );
  return { viewTag, tweak, address };
}

/**
 * Sender side: derive the one-time destination for `meta` from a fresh
 * ephemeral scalar. Publish `ephemeralPub` + `viewTag` (the announcement);
 * pay `address`.
 */
export function deriveStealthAddress(
  meta: StealthMetaAddress,
  ephemeralPriv: FieldInput,
): StealthDerivation {
  const r = checkScalarRange("ephemeralPriv", BigInt(ephemeralPriv), SUBGROUP_ORDER);
  const viewPubPoint = unpackPubkey(meta.viewPub);
  const { viewTag, address } = tweakToAddress(
    parseSpendPub(meta.spendPub),
    ecdhSharedSecret(r, viewPubPoint),
  );
  return { ephemeralPub: packPubkey(mulPointEscalar(Base8, r)), viewTag, address };
}

/**
 * Recipient detection with the VIEW key only: recompute the (viewTag, address)
 * an announcement's `ephemeralPub` would have produced for this identity. The
 * caller matches these against the announcement / on-chain transfer; no spend
 * authority is involved, so this may run on a delegated scanner.
 */
export function scanStealthAnnouncement(
  viewPriv: FieldInput,
  spendPub: string,
  ephemeralPub: string,
): { viewTag: number; address: string } {
  const v = checkScalarRange("viewPriv", BigInt(viewPriv), SUBGROUP_ORDER);
  const { viewTag, address } = tweakToAddress(
    parseSpendPub(spendPub),
    ecdhSharedSecret(v, unpackPubkey(ephemeralPub)),
  );
  return { viewTag, address };
}

/**
 * Recipient spend: reconstruct the one-time EOA's secp256k1 private key
 * (p = spendPriv + tweak mod N). Returns the key in the standard 32-byte hex
 * form wallet tooling accepts, plus the address it controls (recomputed from
 * the key itself, so a mismatched (viewPriv, spendPriv) pair cannot yield a
 * key silently controlling some other address).
 */
export function recoverStealthKey(
  viewPriv: FieldInput,
  spendPriv: FieldInput,
  ephemeralPub: string,
): { privateKey: string; address: string } {
  const v = checkScalarRange("viewPriv", BigInt(viewPriv), SUBGROUP_ORDER);
  const s = checkScalarRange("spendPriv", BigInt(spendPriv), SECP256K1_ORDER);
  const { tweak } = sharedSecretDigest(ecdhSharedSecret(v, unpackPubkey(ephemeralPub)));
  const p = (s + tweak) % SECP256K1_ORDER;
  if (p === 0n) {
    throw new Error("stealth: degenerate zero spend key");
  }
  const priv = le32(p).reverse(); // big-endian 32 bytes, the EOA key wire form
  return {
    privateKey: "0x" + bytesToHex(priv),
    address: addressFromPoint(SecpPoint.BASE.multiply(p)),
  };
}

/**
 * Draw a uniform ephemeral scalar in [1, SUBGROUP_ORDER) from WebCrypto by
 * rejection sampling (mask to the order's bit width, retry out-of-range draws
 * — no modular bias). Deterministic callers (tests, fixtures) pass their own
 * scalar to deriveStealthAddress instead.
 */
export function randomEphemeralScalar(): bigint {
  const bits = SUBGROUP_ORDER.toString(2).length; // 251
  const topByteMask = (1 << (((bits - 1) % 8) + 1)) - 1;
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  for (;;) {
    globalThis.crypto.getRandomValues(bytes);
    bytes[0] &= topByteMask;
    const candidate = bytesToBigIntBE(bytes);
    if (candidate > 0n && candidate < SUBGROUP_ORDER) return candidate;
  }
}

/**
 * Validate a meta-address as received over a wire (the indexer name registry):
 * both keys must decode to valid curve points. Throws with the offending half
 * named, so a 400 can say which field to fix.
 */
export function validateStealthMetaAddress(meta: StealthMetaAddress): void {
  try {
    unpackPubkey(meta.viewPub);
  } catch (e) {
    throw new Error(`viewPub: ${(e as Error).message}`);
  }
  try {
    parseSpendPub(meta.spendPub);
  } catch (e) {
    throw new Error(`spendPub: ${(e as Error).message}`);
  }
}
