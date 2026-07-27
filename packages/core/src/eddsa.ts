// BabyJubJub EdDSA-Poseidon sign/verify for the /notes read-auth (SPEC §6b v2).
//
// The auditor-key indexer decrypts every user's notes, so `GET /notes?owner=` must
// require proof the caller controls the queried key before serving it. The proof
// is a Schnorr/EdDSA signature over a Poseidon-bound message, checked against the
// queried public key. The private key here is the SAME scalar note.ts calls the
// "formatted private key" (the value the circuit consumes and A = s·Base8), so a
// wallet signs with the key it already holds — no separate signing key.
//
//   A   = s·Base8                                    (the public key)
//   r   = Poseidon(s, msg) mod L                     (deterministic nonce, no RNG)
//   R8  = r·Base8
//   h   = Poseidon(R8.x, R8.y, A.x, A.y, msg)
//   S   = (r + h·s) mod L
//   check:  S·Base8 == R8 + h·A
//
// L is the BabyJubJub prime-order subgroup order (curve order >> 3); Base8 has
// order L, so all scalar arithmetic that matters is mod L. The nonce is a Poseidon
// PRF of (key, msg): reproducible (the workflow env forbids Math.random) and, since
// msg binds the pubkey + a fresh timestamp, non-reused across distinct requests.
//
// This is a self-contained reference scheme (Poseidon nonce + Poseidon challenge),
// NOT circomlib's Blake-hashed pruned-scalar EdDSA — it never has to match an
// in-circuit gadget; it only gates an HTTP read. Threat model: signature ==
// spending key (SPEC §5.1), which is exactly the disclosure boundary we want.

import { Base8, addPoint, mulPointEscalar, isOnCurve, P, IDENTITY, SUBGROUP_ORDER } from "./babyjub.js";
import type { FieldInput, Point, PointInput } from "./babyjub.js";
import { poseidonN } from "./poseidon.js";

// The subgroup order L lives with the curve (babyjub.ts); re-exported here so
// existing `@bongtu/core/eddsa` importers keep working.
export { SUBGROUP_ORDER } from "./babyjub.js";

const isIdentity = ([x, y]: Point): boolean => x === IDENTITY[0] && y === IDENTITY[1];

/** An EdDSA-Poseidon signature: the nonce point R8 and the scalar S (< L). */
export interface Signature {
  R8: Point;
  S: bigint;
}

function modL(x: bigint): bigint {
  const r = x % SUBGROUP_ORDER;
  return r < 0n ? r + SUBGROUP_ORDER : r;
}

/**
 * The field element a /notes request signs: Poseidon(ownerPub.x, ownerPub.y, ts).
 * Binding the owner pubkey stops a signature made for one key authorising another;
 * binding the unix-seconds timestamp scopes it to the caller's replay window.
 */
export function notesAuthMessage(ownerPub: PointInput, timestamp: FieldInput): bigint {
  return poseidonN([BigInt(ownerPub[0]), BigInt(ownerPub[1]), BigInt(timestamp)]);
}

/**
 * Domain tag mixed into every VIEW-TOKEN challenge signature — a distinct nonzero
 * constant (ascii "bongtu/viewtoken/v1" read as a big-endian integer, 19 bytes, so
 * comfortably in-field). Its job is domain separation: without it the challenge
 * signature is shape-identical to a `notesAuthMessage(pub, ts)` signature, so a
 * legacy signed-query signature captured off the wire could be redeemed at POST
 * /auth for a 24h token (and vice versa). With the tag AND the wider arity, the two
 * preimages can never collide, so neither message type verifies as the other.
 */
export const VIEWTOKEN_DOMAIN_TAG = 0x626f6e6774752f76696577746f6b656e2f7631n;

/**
 * The field element a POST /auth challenge redemption signs:
 *   Poseidon(ownerPub.x, ownerPub.y, challenge, hostBinding, VIEWTOKEN_DOMAIN_TAG).
 *
 * `hostBinding` is a field-sized digest of the indexer origin the signer is
 * ACTUALLY talking to (`viewTokenHostBinding` in indexerApi.ts). Binding it stops
 * challenge relay: a hostile indexer can proxy a live server's challenge, but the
 * victim signs the HOSTILE origin's binding, and the real server verifies against
 * its OWN binding — so the relayed signature never redeems.
 */
export function viewTokenAuthMessage(
  ownerPub: PointInput,
  challenge: FieldInput,
  hostBinding: FieldInput,
): bigint {
  return poseidonN([
    BigInt(ownerPub[0]),
    BigInt(ownerPub[1]),
    BigInt(challenge),
    BigInt(hostBinding),
    VIEWTOKEN_DOMAIN_TAG,
  ]);
}

/** Sign a field-element message with a BabyJubJub private scalar. Deterministic. */
export function signNotesAuth(privateKey: FieldInput, msg: FieldInput): Signature {
  const s = BigInt(privateKey);
  const m = BigInt(msg);
  const A = mulPointEscalar(Base8, s);
  const r = modL(poseidonN([s, m])); // deterministic nonce — Poseidon PRF, no RNG
  const R8 = mulPointEscalar(Base8, r);
  const h = poseidonN([R8[0], R8[1], A[0], A[1], m]);
  const S = modL(r + h * s);
  return { R8, S };
}

/**
 * Check a signature against the claimed public key + message. Returns false (never
 * throws) for a wrong key, tampered message, or structurally-invalid signature
 * (R8 off-curve, S out of [0, L)).
 */
export function verifyNotesAuth(pubkey: PointInput, msg: FieldInput, sig: Signature): boolean {
  const A: Point = [BigInt(pubkey[0]), BigInt(pubkey[1])];
  const m = BigInt(msg);
  const { R8, S } = sig;
  if (!isOnCurve(A) || !isOnCurve(R8)) return false;
  if (S < 0n || S >= SUBGROUP_ORDER) return false; // canonical S only
  // Reject a pubkey outside the prime-order subgroup (identity / low-order point):
  // for such an A the term h·A can vanish, so S·Base8 == R8 would verify with no
  // private key. Real owner keys are s·Base8, always in the subgroup.
  if (isIdentity(A) || !isIdentity(mulPointEscalar(A, SUBGROUP_ORDER))) return false;
  const h = poseidonN([R8[0], R8[1], A[0], A[1], m]);
  const lhs = mulPointEscalar(Base8, S);
  const rhs = addPoint(R8, mulPointEscalar(A, h));
  return lhs[0] === rhs[0] && lhs[1] === rhs[1];
}

function toHex32(x: bigint): string {
  if (x < 0n) throw new Error("packSignature: negative field element");
  const h = x.toString(16);
  if (h.length > 64) throw new Error("packSignature: field element exceeds 32 bytes");
  return h.padStart(64, "0");
}

/**
 * Encode a signature for a URL query param: "0x" + three 32-byte big-endian field
 * elements (R8.x ‖ R8.y ‖ S) = 192 hex chars. Compact, unambiguous, round-trips.
 */
export function packSignature(sig: Signature): string {
  return "0x" + toHex32(sig.R8[0]) + toHex32(sig.R8[1]) + toHex32(sig.S);
}

/** Parse a packed signature. Throws on a malformed encoding (wrong length / hex). */
export function parseSignature(hex: string): Signature {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length !== 192 || !/^[0-9a-fA-F]{192}$/.test(h)) {
    throw new Error(`parseSignature: expected 0x + 192 hex chars (R8x‖R8y‖S), got ${JSON.stringify(hex)}`);
  }
  const R8x = BigInt("0x" + h.slice(0, 64));
  const R8y = BigInt("0x" + h.slice(64, 128));
  const S = BigInt("0x" + h.slice(128, 192));
  // Canonical only: R8 coordinates < P, S < L. Rejecting non-reduced encodings
  // (e.g. x+P) keeps the signature non-malleable at the wire.
  if (R8x >= P || R8y >= P) throw new Error("parseSignature: R8 coordinate not reduced mod P");
  if (S >= SUBGROUP_ORDER) throw new Error("parseSignature: S not reduced mod L");
  return { R8: [R8x, R8y], S };
}
