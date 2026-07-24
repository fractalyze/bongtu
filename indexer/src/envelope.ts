// Arbiter-mode authority-envelope decrypt + parse (SPEC §6b v2 enforced disclosure).
//
// Every bongtu op encrypts an authority (non-repudiation) envelope to the SINGLE
// arbiter key INSIDE the proof — the contract injects the stored arbiter key
// before verify, so a wrong-key or absent encryption makes the proof fail. The
// envelope carries the op's note fields (owner pubkey, value, salt) for BOTH the
// consumed inputs and the created outputs. Given the arbiter PRIVATE key plus the
// on-chain (ecdhPublicKey, encryptionNonce, ciphertext), the auditor recovers
// those fields with NO user private key and NO nullifier linkage — this is the
// mechanism behind "enforced auditor disclosure".
//
// Decrypt is ECDH + Poseidon-sponge, byte-identical to
// circuits/auditor_decrypt_check.ts:
//   shared    = ecdhSharedSecret(arbiterPriv, ecdhPublicKey)   // == circuit Ecdh(ephemeralPriv, arbiterPub)
//   plaintext = poseidonDecrypt(ct, shared, encryptionNonce, plaintextLen)
// then a per-op layout table slices the flat plaintext into inputs/outputs.
//
// Plaintext layouts (SPEC §4 / the four *_authority circuits):
//   deposit  (0-in/2-out): [o0.x,o0.y, o1.x,o1.y, v0,s0, v1,s1]                  (len 8    -> ct[10])
//   withdraw (2-in/1-out): [inOwn.x,inOwn.y, iv0,is0, iv1,is1, ch.x,ch.y, cv,cs] (len 10   -> ct[13])
//   transfer (2-in/2-out): [inOwn.x,inOwn.y, iv0,is0, iv1,is1,
//                           o0.x,o0.y, o1.x,o1.y, ov0,os0, ov1,os1]              (len 14   -> ct[16])
//   disburse (1-in/B-out): [inOwn.x,inOwn.y, iv,is, (o.x,o.y)*B, (ov,os)*B]      (len 4+4B -> tail)
// transfer/withdraw share ONE input owner across both inputs (the circuit takes a
// single inputOwnerPrivateKey); a padded/disabled input has value 0.

import { ecdhSharedSecret, poseidonDecrypt } from "../../sdk/src/note.js";

export type OpKind = "deposit" | "withdraw" | "transfer" | "disburse";

/** One note recovered from an envelope: owner pubkey point + value + salt. */
export interface EnvNote {
  owner: [bigint, bigint];
  value: bigint;
  salt: bigint;
}
/** The inputs consumed + outputs created by an op, as recovered from its envelope. */
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
