// The authority (non-repudiation) envelope codec — THE consensus artifact.
//
// Every bongtu op encrypts an authority envelope to the SINGLE arbiter key
// INSIDE the proof (.dev/spec-decisions.md §6b v2 enforced disclosure): the contract
// injects the stored arbiter key before verify, so a wrong-key or absent
// encryption makes the proof fail. The envelope carries the op's note fields
// (owner pubkey, value, salt) for BOTH the consumed inputs and the created
// outputs. Given the arbiter PRIVATE key plus the on-chain (ecdhPublicKey,
// encryptionNonce, ciphertext), the auditor recovers those fields with NO user
// private key and NO nullifier linkage — the mechanism behind "enforced
// auditor disclosure".
//
// This module owns BOTH directions, so encoder/decoder drift is structurally
// impossible: buildAuthorityPlaintext is the exact inverse of parseEnvelope,
// and every producer (payroll-web disburse assembly, the deploy runners, the
// indexer scenario) and consumer (indexer arbiter ledger, payroll-web auditor
// ledger) goes through it. TWO deliberate exceptions stay hand-rolled as
// independent checks and must NOT import this module:
// circuits/auditor_decrypt_check.ts (the circuit-parity gate) and
// apps/indexer/test/ingest.test.ts makeSim (the ingest suite's synthetic
// envelope builder).
//
// PLAINTEXT LAYOUTS (.dev/spec-decisions.md §4 / the four *_authority circuits; field
// order is consensus — a reorder passes TS round-trips but breaks auditor
// decryption of live-chain envelopes):
//   deposit    (0-in/ 2-out): [o0.x,o0.y, o1.x,o1.y, v0,s0, v1,s1]                (len 8    -> ct[10])
//   withdraw   (2-in/ 1-out): [inOwn.x,inOwn.y, iv0,is0, iv1,is1, ch.x,ch.y, cv,cs] (len 10 -> ct[13])
//   transfer   (2-in/ 2-out): [inOwn.x,inOwn.y, iv0,is0, iv1,is1,
//                              o0.x,o0.y, o1.x,o1.y, ov0,os0, ov1,os1]            (len 14   -> ct[16])
//   transfer10 (10-in/10-out): the same shape at arity 10                         (len 62   -> ct[64])
//   disburse   (1-in/ B-out): [inOwn.x,inOwn.y, iv,is, (o.x,o.y)*B, (ov,os)*B]    (len 4+4B -> tail)
// All five are ONE layout — an optional shared-input-owner head, then the input
// (value, salt) pairs, then the output owner points, then the output
// (value, salt) pairs — so `spendLayout` below is the single implementation and
// the table above is its instantiation, not a second source of truth. Every
// spending circuit takes a single inputOwnerPrivateKey, so all of an op's inputs
// share ONE owner and it is carried once; deposit mints and has no input head at
// all. A padded/disabled input has value 0 (the §5.2 value-belt: enabled=0 ⟹
// value=0, so a padded slot discloses nothing real).
//
// Encrypt/decrypt is ECDH + Poseidon-sponge, byte-identical to the circuits:
//   shared    = ecdhSharedSecret(arbiterPriv, ecdhPublicKey)   // == circuit Ecdh(ephemeralPriv, arbiterPub)
//   plaintext = poseidonDecrypt(ct, shared, encryptionNonce, plaintextLen)
//
// DISCLOSURE CHAIN (.dev/spec-decisions.md §6b indexer duty, §4/§11-6): a disburse proof
// commits to a Poseidon(2) fold over its emitted ciphertext — every receiver
// element then every authority element, seeded at 0. disclosureChain is that
// fold; the on-chain disclosureHash public signal is its final value, and the
// pin suite (test/envelope.test.ts p2) proves this TS fold equals the
// in-circuit gadget on the committed disburse256 proof fixture.

import type { FieldInput, Point } from "./babyjub.js";
import { hybridEnvelopeKey } from "./kem.js";
import { ecdhSharedSecret, poseidonDecrypt } from "./note.js";
import { poseidon2 } from "./poseidon.js";

export type OpKind = "deposit" | "withdraw" | "transfer" | "transfer10" | "disburse";

/** transfer10 arity: the 10-in / 10-out instantiation of the transfer base
 *  (`circuits/transfer10.circom`). Both sides are 10 — a spend may enable 1..10
 *  inputs (the rest padded) and fund 1..10 outputs (the rest zero-value). */
export const TRANSFER10_ARITY = 10;

/** The (nIn, nOut) an op's envelope covers. `B` is read only by disburse, whose
 *  output count is the pool's batch size; every other kind has a fixed arity. */
function opArity(kind: OpKind, B: number): { nIn: number; nOut: number } {
  switch (kind) {
    case "deposit":
      return { nIn: 0, nOut: 2 };
    case "withdraw":
      return { nIn: 2, nOut: 1 };
    case "transfer":
      return { nIn: 2, nOut: 2 };
    case "transfer10":
      return { nIn: TRANSFER10_ARITY, nOut: TRANSFER10_ARITY };
    case "disburse":
      return { nIn: 1, nOut: B };
  }
}

/** Field offsets of the one envelope layout, at a given arity: the shared input
 *  owner head (present iff nIn > 0), the input (value, salt) run, the output
 *  owner points, then the output (value, salt) run. */
function spendLayout(nIn: number, nOut: number): {
  inValBase: number;
  outOwnBase: number;
  outValBase: number;
  len: number;
} {
  const inValBase = nIn > 0 ? 2 : 0; // after [inOwn.x, inOwn.y]
  const outOwnBase = inValBase + 2 * nIn;
  const outValBase = outOwnBase + 2 * nOut;
  return { inValBase, outOwnBase, outValBase, len: outValBase + 2 * nOut };
}

/** One note carried by an envelope: owner pubkey point + value + salt. */
export interface EnvNote {
  owner: Point;
  value: bigint;
  salt: bigint;
}
/** The inputs consumed + outputs created by an op, as carried by its envelope. */
export interface ParsedEnvelope {
  inputs: EnvNote[];
  outputs: EnvNote[];
}

/** Plaintext field count for an op's authority envelope (disburse scales with B).
 *  deposit 8, withdraw 10, transfer 14, transfer10 62, disburse 4 + 4B. */
export function envelopePlaintextLen(kind: OpKind, B: number): number {
  const { nIn, nOut } = opArity(kind, B);
  return spendLayout(nIn, nOut).len;
}

/** Poseidon-sponge ciphertext length for an op's authority envelope: the
 *  plaintext padded to a multiple of 3, plus the sponge's final squeeze.
 *  disburse B=256 -> 1030, so 4*B + 1030 == 2054 == disburseCiphertextLen;
 *  transfer10 -> 64, the `cipherTextAuthority[64]` the circuit publishes. */
export function authorityCiphertextLen(kind: OpKind, B: number): number {
  const plain = envelopePlaintextLen(kind, B);
  return plain + ((3 - (plain % 3)) % 3) + 1;
}

/**
 * Lay out an op's authority-envelope plaintext (the exact inverse of
 * parseEnvelope; the field order above is the consensus artifact). Callers
 * encrypt the result with poseidonEncrypt(plain, ecdhSharedSecret(ecdhPriv,
 * arbiterPub), nonce). For disburse, B = outputs.length (real recipients ++
 * change ++ zero-value pads, exactly the circuit's output vector).
 *
 * Throws on a shape that no circuit produces: wrong input/output counts for
 * the kind, or transfer/withdraw inputs with differing owners (the circuits
 * take a single inputOwnerPrivateKey).
 */
export function buildAuthorityPlaintext(kind: OpKind, env: ParsedEnvelope): bigint[] {
  const { inputs, outputs } = env;
  const need = (cond: boolean, msg: string): void => {
    if (!cond) throw new Error(`buildAuthorityPlaintext(${kind}): ${msg}`);
  };

  // disburse is the one kind whose output count is not fixed by the circuit tag.
  const { nIn, nOut } = opArity(kind, outputs.length);
  if (kind === "disburse") {
    need(outputs.length > 0, "disburse needs B >= 1 outputs");
  } else {
    // withdraw's single output IS the change note — the wording is pinned by the
    // builder-rejects test, so name it rather than saying "1 outputs".
    const noun = kind === "withdraw" ? "change output" : `output${nOut === 1 ? "" : "s"}`;
    need(outputs.length === nOut, `${kind} creates exactly ${nOut} ${noun} (got ${outputs.length})`);
  }
  need(
    inputs.length === nIn,
    nIn === 0
      ? `${kind} consumes no inputs (got ${inputs.length})`
      : `${kind} consumes exactly ${nIn} input${nIn === 1 ? "" : "s"} (got ${inputs.length})`,
  );
  for (const i of inputs) {
    need(
      i.owner[0] === inputs[0].owner[0] && i.owner[1] === inputs[0].owner[1],
      "all inputs must share ONE owner (the circuit takes a single inputOwnerPrivateKey)",
    );
  }

  return [
    ...(nIn > 0 ? [inputs[0].owner[0], inputs[0].owner[1]] : []),
    ...inputs.flatMap((i) => [i.value, i.salt]),
    ...outputs.flatMap((o) => [o.owner[0], o.owner[1]]),
    ...outputs.flatMap((o) => [o.value, o.salt]),
  ];
}

/**
 * Decrypt + parse an op's authority envelope with the arbiter private key.
 *
 * `ct` is the authority ciphertext ONLY. For disburse that is the TAIL after the
 * 4*B receiver elements (the receiver run is keyed to each recipient, not to the
 * arbiter); deposit/withdraw/transfer publish the authority ciphertext on its own.
 *
 * `kemSs` (pq-envelope-design.md §2/§5): the ML-KEM-768 shared-secret limbs the
 * arbiter decapsulated from the op's kemCiphertext. Present -> the envelope key
 * is the tagged hybrid Poseidon fold; absent -> the legacy raw-ECDH-point key
 * (pre-KEM ops decode under the V1 event ABI with no kem fields).
 */
export function parseEnvelope(
  arbiterPriv: bigint,
  ecdhPublicKey: [bigint, bigint],
  nonce: bigint,
  ct: bigint[],
  kind: OpKind,
  B: number,
  kemSs?: [FieldInput, FieldInput],
): ParsedEnvelope {
  const shared = ecdhSharedSecret(arbiterPriv, ecdhPublicKey);
  const key = kemSs ? hybridEnvelopeKey(shared, kemSs) : shared;
  const { nIn, nOut } = opArity(kind, B);
  const { inValBase, outOwnBase, outValBase, len } = spendLayout(nIn, nOut);
  const m = poseidonDecrypt(ct, key, nonce, len);

  // One shared input owner for every input (the circuits take a single
  // inputOwnerPrivateKey); deposit mints and carries no input head.
  const inOwn: [bigint, bigint] = nIn > 0 ? [m[0], m[1]] : [0n, 0n];
  const inputs: EnvNote[] = [];
  for (let i = 0; i < nIn; i++) {
    inputs.push({ owner: inOwn, value: m[inValBase + 2 * i], salt: m[inValBase + 2 * i + 1] });
  }
  const outputs: EnvNote[] = [];
  for (let i = 0; i < nOut; i++) {
    outputs.push({
      owner: [m[outOwnBase + 2 * i], m[outOwnBase + 2 * i + 1]],
      value: m[outValBase + 2 * i],
      salt: m[outValBase + 2 * i + 1],
    });
  }
  return { inputs, outputs };
}

/** Poseidon(2) fold of a ciphertext element list, seeded at 0 — the disburse
 *  disclosure chain. Fold receiver elements then authority elements (i.e. pass
 *  [...receiverFlat, ...authorityCt]); the final value equals the proof's
 *  disclosureHash public signal. */
export function disclosureChain(elements: bigint[]): bigint {
  let dh = 0n;
  for (const x of elements) dh = poseidon2(dh, x);
  return dh;
}
