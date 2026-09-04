// Consumer (no-auditor) note-layer crypto — the TS side of OPMOD §3
// (.dev/op-module-design.md). The five consumer circuits derive the SAME
// values in-circuit; drift here breaks recipient discovery of live consumer
// notes, so the tag literals below are FROZEN (sha256(ASCII) mod r, computed
// 2026-09-03) and must stay byte-equal to the circuit literals.
//
//   S_i          = Ecdh(ephemeralPriv, viewPub_i)          // bjj, per-output; VIEW key, not spend
//   (ct_i, ss_i) = ML-KEM-768.Encaps(kemEk_i)              // per-output, fresh
//   kemSs_i      = kemSsToLimbs(ss_i)                      // two LE-uint128 limbs (kem.ts)
//   rk_i[j]      = Poseidon(5)([TAG_RKj, S_i.x, S_i.y, kemSs_i[0], kemSs_i[1]])
//   tagField_i   = Poseidon(3)([TAG_VIEWTAG, S_i.x, S_i.y])
//   viewTag_i    = tagField_i mod 2^8                      // canonical low 8 bits (OPMOD §3.2)
//   cipherTexts[i] = SymmetricEncrypt(2)([value_i, salt_i], key = rk_i,
//                                        nonce = encryptionNonce + i)   // OPMOD §3.5 (U-X3 rule)
//
// Same shape as the arbiter hybrid envelope key (kem.ts / docs/protocol.md
// § The hybrid envelope key) minus the binding output: there is no arbiter to
// alarm, and a junk encapsulation self-sabotages only the sender's own
// delivery — the recipient's commitment-vs-leaf acceptance (the leaf-match MAC
// substitute, packages/client/src/balance.ts trialDecryptEvents) rejects the
// garbage decrypt while the note's funds stay intact. No per-output kemBinding
// exists (OPMOD §2/§3.3).
//
// The viewTag hashes the ECDH shared secret ONLY (not the KEM secret), so a
// scanner holding just viewPriv can pre-filter ~256× before any Decaps; the
// in-circuit twin decomposes tagField with Num2Bits_strict so the published
// tag is canonical — the TS mask below is canonical by construction because
// BigInt arithmetic mod p never leaves [0, p).
//
// disbursePriv256 disclosure (OPMOD §4.2): three contiguous runs in leaf
// order — receiverCts[4B] ++ viewTags[B] ++ outputCommitments[B] — folded by
// the SAME Poseidon(2) chain as the enterprise disclosureHash
// (envelope.ts disclosureChain, seeded at 0). The two families' folds are
// domain-separated by construction (different element counts and content
// classes; each verifier only meets its own family's proofs).
//
// Browser-safe: no node builtins.

import type { FieldInput, Point, PointInput } from "@bongtu/core/babyjub";
import { disclosureChain } from "@bongtu/core/envelope";
import { kemSsToLimbs, ml_kem768 } from "@bongtu/core/kem";
import { ecdhSharedSecret, poseidonDecrypt, poseidonEncrypt } from "@bongtu/core/note";
import { FIELD_PRIME, poseidonN } from "@bongtu/core/poseidon";

// Domain-separation tags: sha256(ASCII) mod r (BN254 scalar field), frozen
// 2026-09-03 (OPMOD §3.3). NEW strings — the arbiter tags
// (bongtu/pq-envelope/v1/*, kem.ts) are never reused.
//   TAG_RK0     = sha256("bongtu/consumer-note/v1/key0")    mod r
//   TAG_RK1     = sha256("bongtu/consumer-note/v1/key1")    mod r
//   TAG_VIEWTAG = sha256("bongtu/consumer-note/v1/viewtag") mod r
export const TAG_RK0 =
  15911670041651909454486960207337169366505934455020053916031847212914070689294n;
export const TAG_RK1 =
  18959445568053998966444410456355743824415104493789084861475706421378089710793n;
export const TAG_VIEWTAG =
  4236837455644426462098222144565872234823396873019476831333450393757091506254n;

/** A consumer receiver ciphertext is SymmetricEncrypt(2) of [value, salt]:
 *  2 plaintext elements -> 3 sponge elements + 1 squeeze = 4. */
export const CONSUMER_CT_LEN = 4;

const TWO128 = 1n << 128n;
const TWO8 = 256n;

/** Guard the S3.5 nonce+index packing: encryptionNonce is client-clamped to
 *  < 2^128 and the per-output offset must not escape the sponge's nonce slot
 *  (nonce + i >= 2^128 only at nonce >= 2^128 - 255, excluded by the clamp). */
function offsetNonce(encryptionNonce: FieldInput, index: number): bigint {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`consumer: output index must be a non-negative integer (got ${index})`);
  }
  const nonce = BigInt(encryptionNonce) + BigInt(index);
  if (nonce >= TWO128) {
    throw new Error("consumer: encryptionNonce + index escapes the 128-bit nonce slot");
  }
  return nonce;
}

/** The hybrid receiver key (OPMOD §3.3): folds the per-output ECDH point and
 *  the per-output ML-KEM limbs through tagged Poseidon(5) — equals the
 *  circuits' receiver `key[2]`, and is the key for poseidonEncrypt/
 *  poseidonDecrypt of the [value, salt] receiver ciphertext. */
export function hybridReceiverKey(
  ecdhShared: PointInput,
  kemSs: [FieldInput, FieldInput],
): [bigint, bigint] {
  const tail = [BigInt(ecdhShared[0]), BigInt(ecdhShared[1]), BigInt(kemSs[0]), BigInt(kemSs[1])];
  return [poseidonN([TAG_RK0, ...tail]), poseidonN([TAG_RK1, ...tail])];
}

/** The canonical low-8-bit view tag of a tag field element (OPMOD §3.2).
 *  BigInt values in [0, p) have exactly one encoding, so masking IS the
 *  canonical little-endian bits 0..7 — the value Num2Bits_strict recomposes
 *  in-circuit. Range-checked so a non-reduced input (which WOULD alias) is a
 *  caller bug, not a silent wrong tag. */
export function viewTagFromField(tagField: FieldInput): bigint {
  const t = BigInt(tagField);
  if (t < 0n || t >= FIELD_PRIME) {
    throw new Error("viewTagFromField: tag field element out of range [0, p)");
  }
  return t % TWO8;
}

/** viewTag_i = Poseidon(3)([TAG_VIEWTAG, S.x, S.y]) mod 2^8 over the per-output
 *  ECDH shared point. Deliberately KEM-free: a viewPriv-only scanner can
 *  pre-filter without Decaps (OPMOD §3.2). */
export function consumerViewTag(ecdhShared: PointInput): bigint {
  return viewTagFromField(poseidonN([TAG_VIEWTAG, BigInt(ecdhShared[0]), BigInt(ecdhShared[1])]));
}

/** Encrypt one consumer output note [value, salt] under a derived receiver key
 *  at output position `index` — the OPMOD §3.5 per-output nonce rule
 *  (encryptionNonce + index), uniform across all five consumer circuits. */
export function encryptConsumerNote(
  value: FieldInput,
  salt: FieldInput,
  receiverKey: PointInput,
  encryptionNonce: FieldInput,
  index: number,
): bigint[] {
  return poseidonEncrypt([BigInt(value), BigInt(salt)], receiverKey, offsetNonce(encryptionNonce, index));
}

/** Inverse of encryptConsumerNote. No MAC: the caller MUST accept the result
 *  only on commitment-vs-leaf equality (the leaf-match test). */
export function decryptConsumerNote(
  cipherText: FieldInput[],
  receiverKey: PointInput,
  encryptionNonce: FieldInput,
  index: number,
): [bigint, bigint] {
  if (cipherText.length !== CONSUMER_CT_LEN) {
    throw new Error(
      `decryptConsumerNote: consumer receiver ct is ${CONSUMER_CT_LEN} elements, got ${cipherText.length}`,
    );
  }
  const [value, salt] = poseidonDecrypt(cipherText, receiverKey, offsetNonce(encryptionNonce, index), 2);
  return [value, salt];
}

/** Everything the sender publishes (or carries as witness) for one output. */
export interface SealedConsumerOutput {
  /** the 4-element receiver ciphertext — a `cipherTexts[i]` public run. */
  cipherText: bigint[];
  /** the `viewTags[i]` public signal. */
  viewTag: bigint;
  /** the 1088-byte ML-KEM-768 encapsulation — calldata transport (OPMOD §3.4). */
  kemCiphertext: Uint8Array;
  /** the two LE-uint128 shared-secret limbs — PRIVATE witness (`kemSs_i`). */
  kemSs: [bigint, bigint];
  /** the derived hybrid key — PRIVATE, for witness assembly / debugging. */
  receiverKey: [bigint, bigint];
  /** the per-output ECDH shared point — PRIVATE witness. */
  ecdhShared: Point;
}

/** Sender side of OPMOD §3.3 for one output: ECDH against the recipient's
 *  note-layer VIEW pubkey (never the spend key), a fresh ML-KEM-768
 *  encapsulation against their registered ek, the tagged hybrid key, the
 *  ciphertext at nonce+index, and the view tag. `encapSeed` (32 bytes) makes
 *  the encapsulation deterministic for fixtures; omit it in production. */
export function sealConsumerOutput(args: {
  value: FieldInput;
  salt: FieldInput;
  ephemeralPriv: FieldInput;
  viewPub: PointInput;
  kemEk: Uint8Array;
  encryptionNonce: FieldInput;
  index: number;
  encapSeed?: Uint8Array;
}): SealedConsumerOutput {
  const ecdhShared = ecdhSharedSecret(args.ephemeralPriv, args.viewPub);
  const { cipherText: kemCiphertext, sharedSecret } = ml_kem768.encapsulate(
    args.kemEk,
    args.encapSeed,
  );
  const kemSs = kemSsToLimbs(sharedSecret);
  const receiverKey = hybridReceiverKey(ecdhShared, kemSs);
  return {
    cipherText: encryptConsumerNote(args.value, args.salt, receiverKey, args.encryptionNonce, args.index),
    viewTag: consumerViewTag(ecdhShared),
    kemCiphertext,
    kemSs,
    receiverKey,
    ecdhShared,
  };
}

/** Recipient side (the OPMOD §3.6 pipeline, minus the leaf-match): Decaps with
 *  the note-layer view identity (viewPriv + kemDk — neither can spend), derive
 *  the hybrid key, decrypt at nonce+index. Returns the candidate note fields
 *  plus the recomputed viewTag; the caller accepts ONLY on
 *  commitment(value, salt, spendPub) == the on-chain leaf. A junk kem ct never
 *  throws (implicit rejection yields pseudorandom ss) — it surfaces as a
 *  leaf-match failure, the S3.3 sender-self-sabotage class. */
export function openConsumerOutput(args: {
  cipherText: FieldInput[];
  ecdhPublicKey: PointInput;
  viewPriv: FieldInput;
  kemDk: Uint8Array;
  kemCiphertext: Uint8Array;
  encryptionNonce: FieldInput;
  index: number;
}): { value: bigint; salt: bigint; viewTag: bigint } {
  const ecdhShared = ecdhSharedSecret(args.viewPriv, args.ecdhPublicKey);
  const kemSs = kemSsToLimbs(ml_kem768.decapsulate(args.kemCiphertext, args.kemDk));
  const receiverKey = hybridReceiverKey(ecdhShared, kemSs);
  const [value, salt] = decryptConsumerNote(
    args.cipherText,
    receiverKey,
    args.encryptionNonce,
    args.index,
  );
  return { value, salt, viewTag: consumerViewTag(ecdhShared) };
}

/** disclosure length for a B-output consumer batch: 4B cts + B tags + B
 *  commitments (OPMOD §4.1; 1536 at B=256). */
export function consumerDisclosureLen(B: number): number {
  return 6 * B;
}

/**
 * Lay out a consumer batch's `disclosure` calldata array (OPMOD §4.1/§4.2):
 * three contiguous runs, each in leaf order from the batch start —
 * receiver cts flattened at 4i+j, then all viewTags, then all output
 * commitments. The order is total and consensus; any permutation is a
 * different disclosureHash.
 */
export function consumerDisclosureElements(
  receiverCts: readonly (readonly FieldInput[])[],
  viewTags: readonly FieldInput[],
  outputCommitments: readonly FieldInput[],
): bigint[] {
  const B = outputCommitments.length;
  if (B === 0) throw new Error("consumerDisclosureElements: a batch has B >= 1 outputs");
  if (receiverCts.length !== B || viewTags.length !== B) {
    throw new Error(
      `consumerDisclosureElements: runs disagree on B (cts ${receiverCts.length}, ` +
        `tags ${viewTags.length}, commitments ${B})`,
    );
  }
  for (const [i, ct] of receiverCts.entries()) {
    if (ct.length !== CONSUMER_CT_LEN) {
      throw new Error(
        `consumerDisclosureElements: receiver ct ${i} is ${ct.length} elements, want ${CONSUMER_CT_LEN}`,
      );
    }
  }
  return [
    ...receiverCts.flatMap((ct) => ct.map((x) => BigInt(x))),
    ...viewTags.map((x) => BigInt(x)),
    ...outputCommitments.map((x) => BigInt(x)),
  ];
}

/** The extended fold (OPMOD §4.2): the SAME Poseidon(2) chain as the
 *  enterprise disclosureHash (disclosureChain, seeded at 0) over the §4.1
 *  layout — equals the disbursePriv256 proof's `disclosureHash` output. */
export function consumerDisclosureHash(
  receiverCts: readonly (readonly FieldInput[])[],
  viewTags: readonly FieldInput[],
  outputCommitments: readonly FieldInput[],
): bigint {
  return disclosureChain(consumerDisclosureElements(receiverCts, viewTags, outputCommitments));
}
