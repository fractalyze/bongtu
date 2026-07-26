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
// and every producer (admin-web disburse assembly, the deploy runners, the
// indexer scenario) and consumer (indexer arbiter ledger, admin-web auditor
// ledger) goes through it. TWO deliberate exceptions stay hand-rolled as
// independent checks and must NOT import this module:
// circuits/auditor_decrypt_check.ts (the circuit-parity gate) and
// apps/indexer/test/ingest.test.ts makeSim (the ingest suite's synthetic
// envelope builder).
//
// PLAINTEXT LAYOUTS (.dev/spec-decisions.md §4 / the four *_authority circuits; field
// order is consensus — a reorder passes TS round-trips but breaks auditor
// decryption of live-chain envelopes):
//   deposit  (0-in/2-out): [o0.x,o0.y, o1.x,o1.y, v0,s0, v1,s1]                  (len 8    -> ct[10])
//   withdraw (2-in/1-out): [inOwn.x,inOwn.y, iv0,is0, iv1,is1, ch.x,ch.y, cv,cs] (len 10   -> ct[13])
//   transfer (2-in/2-out): [inOwn.x,inOwn.y, iv0,is0, iv1,is1,
//                           o0.x,o0.y, o1.x,o1.y, ov0,os0, ov1,os1]              (len 14   -> ct[16])
//   disburse (1-in/B-out): [inOwn.x,inOwn.y, iv,is, (o.x,o.y)*B, (ov,os)*B]      (len 4+4B -> tail)
// transfer/withdraw share ONE input owner across both inputs (the circuit takes
// a single inputOwnerPrivateKey); a padded/disabled input has value 0 (the §5.2
// value-belt: enabled=0 ⟹ value=0, so a padded slot discloses nothing real).
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

import type { Point } from "./babyjub.js";
import { ecdhSharedSecret, poseidonDecrypt } from "./note.js";
import { poseidon2 } from "./poseidon.js";

export type OpKind = "deposit" | "withdraw" | "transfer" | "disburse";

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

/** Plaintext field count for an op's authority envelope (disburse scales with B). */
export function envelopePlaintextLen(kind: OpKind, B: number): number {
  switch (kind) {
    case "deposit":
      return 8;
    case "withdraw":
      return 10;
    case "transfer":
      return 14;
    case "disburse":
      return 4 + 4 * B;
  }
}

/** Poseidon-sponge ciphertext length for an op's authority envelope: the
 *  plaintext padded to a multiple of 3, plus the sponge's final squeeze.
 *  disburse B=256 -> 1030, so 4*B + 1030 == 2054 == disburseCiphertextLen. */
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
  const sharedInputOwner = (): void =>
    need(
      inputs[0].owner[0] === inputs[1].owner[0] && inputs[0].owner[1] === inputs[1].owner[1],
      "both inputs must share ONE owner (the circuit takes a single inputOwnerPrivateKey)",
    );

  switch (kind) {
    case "deposit":
      need(inputs.length === 0, `deposit consumes no inputs (got ${inputs.length})`);
      need(outputs.length === 2, `deposit creates exactly 2 outputs (got ${outputs.length})`);
      return [
        outputs[0].owner[0], outputs[0].owner[1],
        outputs[1].owner[0], outputs[1].owner[1],
        outputs[0].value, outputs[0].salt,
        outputs[1].value, outputs[1].salt,
      ];
    case "withdraw":
      need(inputs.length === 2, `withdraw consumes exactly 2 inputs (got ${inputs.length})`);
      need(outputs.length === 1, `withdraw creates exactly 1 change output (got ${outputs.length})`);
      sharedInputOwner();
      return [
        inputs[0].owner[0], inputs[0].owner[1],
        inputs[0].value, inputs[0].salt,
        inputs[1].value, inputs[1].salt,
        outputs[0].owner[0], outputs[0].owner[1],
        outputs[0].value, outputs[0].salt,
      ];
    case "transfer":
      need(inputs.length === 2, `transfer consumes exactly 2 inputs (got ${inputs.length})`);
      need(outputs.length === 2, `transfer creates exactly 2 outputs (got ${outputs.length})`);
      sharedInputOwner();
      return [
        inputs[0].owner[0], inputs[0].owner[1],
        inputs[0].value, inputs[0].salt,
        inputs[1].value, inputs[1].salt,
        outputs[0].owner[0], outputs[0].owner[1],
        outputs[1].owner[0], outputs[1].owner[1],
        outputs[0].value, outputs[0].salt,
        outputs[1].value, outputs[1].salt,
      ];
    case "disburse":
      need(inputs.length === 1, `disburse consumes exactly 1 input (got ${inputs.length})`);
      need(outputs.length > 0, "disburse needs B >= 1 outputs");
      return [
        inputs[0].owner[0], inputs[0].owner[1],
        inputs[0].value, inputs[0].salt,
        ...outputs.flatMap((o) => [o.owner[0], o.owner[1]]),
        ...outputs.flatMap((o) => [o.value, o.salt]),
      ];
  }
}

/**
 * Decrypt + parse an op's authority envelope with the arbiter private key.
 *
 * `ct` is the authority ciphertext ONLY. For disburse that is the TAIL after the
 * 4*B receiver elements (the receiver run is keyed to each recipient, not to the
 * arbiter); deposit/withdraw/transfer publish the authority ciphertext on its own.
 */
export function parseEnvelope(
  arbiterPriv: bigint,
  ecdhPublicKey: [bigint, bigint],
  nonce: bigint,
  ct: bigint[],
  kind: OpKind,
  B: number,
): ParsedEnvelope {
  const shared = ecdhSharedSecret(arbiterPriv, ecdhPublicKey);
  const m = poseidonDecrypt(ct, shared, nonce, envelopePlaintextLen(kind, B));

  switch (kind) {
    case "deposit":
      return {
        inputs: [],
        outputs: [
          { owner: [m[0], m[1]], value: m[4], salt: m[5] },
          { owner: [m[2], m[3]], value: m[6], salt: m[7] },
        ],
      };
    case "withdraw": {
      const inOwn: [bigint, bigint] = [m[0], m[1]];
      return {
        inputs: [
          { owner: inOwn, value: m[2], salt: m[3] },
          { owner: inOwn, value: m[4], salt: m[5] },
        ],
        outputs: [{ owner: [m[6], m[7]], value: m[8], salt: m[9] }],
      };
    }
    case "transfer": {
      const inOwn: [bigint, bigint] = [m[0], m[1]];
      return {
        inputs: [
          { owner: inOwn, value: m[2], salt: m[3] },
          { owner: inOwn, value: m[4], salt: m[5] },
        ],
        outputs: [
          { owner: [m[6], m[7]], value: m[10], salt: m[11] },
          { owner: [m[8], m[9]], value: m[12], salt: m[13] },
        ],
      };
    }
    case "disburse": {
      const inOwn: [bigint, bigint] = [m[0], m[1]];
      const ownBase = 4; // (o.x,o.y) pairs start after [inOwn.x, inOwn.y, iv, is]
      const valBase = 4 + 2 * B; // (ov,os) pairs start after the B owner pairs
      const outputs: EnvNote[] = [];
      for (let i = 0; i < B; i++) {
        outputs.push({
          owner: [m[ownBase + 2 * i], m[ownBase + 2 * i + 1]],
          value: m[valBase + 2 * i],
          salt: m[valBase + 2 * i + 1],
        });
      }
      return { inputs: [{ owner: inOwn, value: m[2], salt: m[3] }], outputs };
    }
  }
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
