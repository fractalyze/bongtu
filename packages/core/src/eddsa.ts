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
//
// The VIEW-TOKEN contract lives here too (domain tag, signed tuple, challenge
// width + validity, host binding): it is the same read-auth question asked with a
// server-drawn nonce instead of a timestamp, and both halves — the indexer that
// issues and the client that signs — must agree on every piece of it. indexerApi.ts
// re-exports the client-facing ones so the fetch flows keep one import path.

import { sha256 } from "@noble/hashes/sha2.js";
import { Base8, addPoint, mulPointEscalar, isOnCurve, P, IDENTITY, SUBGROUP_ORDER } from "@bongtu/core/babyjub";
import type { FieldInput, Point, PointInput } from "@bongtu/core/babyjub";
import { poseidonN } from "@bongtu/core/poseidon";

// The subgroup order L lives with the curve (babyjub.ts); re-exported here so
// existing `@bongtu/core/eddsa` importers keep working.
export { SUBGROUP_ORDER } from "@bongtu/core/babyjub";

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
 * ACTUALLY talking to (`viewTokenHostBinding`, below). Binding it stops
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

/** How many random bytes the challenge issuer draws — ONE constant for both
 *  halves: the indexer's `randomBytes(CHALLENGE_BYTES)` (api/viewtoken.ts) and the
 *  client's refusal bound below. 31 bytes is < 2^248, safely under the bn254 field
 *  prime, so every drawn challenge is a valid Poseidon input on both sides. */
export const CHALLENGE_BYTES = 31;
const CHALLENGE_MAX_EXCLUSIVE = 1n << BigInt(8 * CHALLENGE_BYTES);

/**
 * Refuse to sign anything that is not a well-formed challenge. A signature is a
 * blank cheque over whatever preimage the server chose, so the client checks the
 * shape ITSELF rather than trusting the server: decimal digits only, no leading
 * zero, nonzero, and inside the byte range the issuer draws from. A server that
 * hands back an out-of-range or non-decimal "challenge" is malfunctioning or
 * hostile — either way we stop before the key is used.
 */
export function assertValidChallenge(challenge: unknown): bigint {
  if (typeof challenge !== "string" || !/^[1-9][0-9]{0,77}$/.test(challenge)) {
    throw new Error(`indexer returned a malformed challenge (expected a positive decimal): ${JSON.stringify(challenge)}`);
  }
  const v = BigInt(challenge);
  if (v >= CHALLENGE_MAX_EXCLUSIVE) {
    throw new Error(`indexer returned an out-of-range challenge (expected < 2^${8 * CHALLENGE_BYTES})`);
  }
  return v;
}

/** How much of sha256(origin) the host binding keeps. Its own constant because it
 *  answers a DIFFERENT question than CHALLENGE_BYTES — how many digest bytes a
 *  Poseidon input may carry and stay under the field prime — and only happens to
 *  land on the same number. Changing one must not silently move the other. */
export const HOST_BINDING_BYTES = 31;

/**
 * The field element that pins a view-token signature to ONE indexer origin:
 * the first 31 bytes of sha256(origin), as a decimal string.
 *
 * `origin` is scheme + host + port of the URL the caller is actually talking to
 * (path, query and trailing slash dropped, lowercased) — so `http://host:8600`
 * and `http://host:8600/notes` bind identically, while a different host or scheme
 * never can. Both halves compute this from the URL THEY see: the wallet from the
 * indexer base it dials, the indexer from PUBLIC_URL. That asymmetry is the
 * anti-relay property (see viewTokenAuthMessage).
 *
 * A RELATIVE base (the wallet's default `/indexer`, a same-origin reverse proxy)
 * resolves against the page origin — which is genuinely the origin the browser
 * talks to, and therefore what the indexer's PUBLIC_URL must name in a proxied
 * deployment. Outside a browser there is no page, so it resolves against
 * localhost.
 */
export function viewTokenHostBinding(url: string): string {
  const pageOrigin = (globalThis as { location?: { origin?: string } }).location?.origin;
  const u = new URL(url.replace(/\/$/, ""), pageOrigin ?? "http://localhost");
  const digest = sha256(new TextEncoder().encode(u.origin.toLowerCase()));
  return digest.slice(0, HOST_BINDING_BYTES).reduce<bigint>((x, b) => (x << 8n) | BigInt(b), 0n).toString();
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

// ---- name-directory registration auth (indexer /names) ----------------------
//
// Same EdDSA-Poseidon primitive as the reads above, domain-separated so a name
// registration can never be redeemed as a /notes query or a view-token
// challenge (and vice versa). The binding digests the FULL payload, so one
// signature authorises exactly one (name -> stealth meta) mapping.

/** How many digest bytes fold into the binding field element — 31 bytes is
 *  < 2^248, always a valid bn254 field element. */
const NAME_BINDING_BYTES = 31;

const foldDigest = (digest: Uint8Array): bigint =>
  digest.slice(0, NAME_BINDING_BYTES).reduce<bigint>((x, b) => (x << 8n) | BigInt(b), 0n);

// Fixed tag: sha256("bongtu/name-auth-v1") folded the same way as the binding.
const NAME_DOMAIN_TAG: bigint = foldDigest(sha256(new TextEncoder().encode("bongtu/name-auth-v1")));

// The v2 (consumer-triple) domain tag — sha256("bongtu/name-auth-v2") folded the
// same way as v1's, so no v1 signature can verify as v2 or vice versa,
// regardless of what characters a name contains (OPMOD §6.4).
const NAME_DOMAIN_TAG_V2: bigint = foldDigest(sha256(new TextEncoder().encode("bongtu/name-auth-v2")));

/** Field element binding a registration payload: name + both stealth meta keys
 *  (case-normalised hex, so client and server digest identical bytes). */
export function nameBindingField(name: string, viewPub: string, spendPub: string): bigint {
  return foldDigest(
    sha256(new TextEncoder().encode(`${name}|${viewPub.toLowerCase()}|${spendPub.toLowerCase()}`)),
  );
}

/** The message an owner signs to (re)register a name (routes/names.ts). */
export function nameAuthMessage(
  ownerPub: PointInput,
  binding: FieldInput,
  timestamp: FieldInput,
): bigint {
  return poseidonN([
    BigInt(ownerPub[0]),
    BigInt(ownerPub[1]),
    BigInt(binding),
    BigInt(timestamp),
    NAME_DOMAIN_TAG,
  ]);
}

// ---- v2: the consumer registry triple (OPMOD §6.4) --------------------------
//
// Post-op-module, a registration may carry the note-layer consumer identity —
// (noteViewPub, kemEk) — beside the legacy stealth meta. The v2 digest is
// ALWAYS five segments, with explicit full-width zero-sentinels when the
// consumer pair is absent, so absence is a signed statement rather than an
// encoding ambiguity; and it is wrapped under the SEPARATE v2 domain tag.

/** The v2 zero-sentinel for an absent/cleared `noteViewPub` (32 zero bytes). */
export const NOTE_VIEW_PUB_ZERO = "0x" + "0".repeat(64);
/** The v2 zero-sentinel for an absent/cleared `kemEk` (1184 zero bytes). */
export const KEM_EK_ZERO = "0x" + "0".repeat(2368);

/** Field element binding a v2 registration payload — five segments ALWAYS
 *  (pass the zero-sentinels for an absent consumer pair). */
export function nameBindingFieldV2(
  name: string,
  viewPub: string,
  spendPub: string,
  noteViewPub: string,
  kemEk: string,
): bigint {
  return foldDigest(
    sha256(
      new TextEncoder().encode(
        `${name}|${viewPub.toLowerCase()}|${spendPub.toLowerCase()}|${noteViewPub.toLowerCase()}|${kemEk.toLowerCase()}`,
      ),
    ),
  );
}

/** The message an owner signs for a v2 (consumer-triple) registration. Same
 *  tuple shape as v1's, under the v2 domain tag — the two can never verify as
 *  each other. */
export function nameAuthMessageV2(
  ownerPub: PointInput,
  binding: FieldInput,
  timestamp: FieldInput,
): bigint {
  return poseidonN([
    BigInt(ownerPub[0]),
    BigInt(ownerPub[1]),
    BigInt(binding),
    BigInt(timestamp),
    NAME_DOMAIN_TAG_V2,
  ]);
}
