// txbuild/data.ts — consumer op instruction DATA from prover calldata: the
// third consumer of the ONE per-op layout table (@bongtu/core/solanaOps,
// beside the vector generators and the indexer's ledger decoder). No local
// index literal exists in this file: which publics ride the wire, in what
// order, at what discriminator, all come from the table — hand-transcribing a
// layout index here is the drift class the table was built to end.
//
// Wire shape per op (chains/solana/program/src/<op>.rs, SOLR §2.3):
//   discriminator(1) || proof(PROOF_LEN) || carried publics (32 B BE each) ||
//   kemCtCount × KEM_CT_LEN || stealthTailLen bytes
// Field elements are 32-byte BIG-ENDIAN — the one canonical byte form on this
// rail (@bongtu/core/solana module doc).

import type { Calldata } from "@bongtu/core/proving";
import { KEM_CT_LEN, PROOF_LEN } from "@bongtu/core/solana";
import { SOLANA_OPS, wireLenOf, type SolanaOpName } from "@bongtu/core/solanaOps";

/** The four consumer-family ops this client builds transactions for. */
export type ConsumerOpName = "depositPriv" | "transferPriv" | "transfer10x2Priv" | "withdrawPriv";

const hexToBytes = (hex: string): Uint8Array => {
  const h = hex.replace(/^0x/, "");
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error(`invalid hex: ${hex.slice(0, 18)}…`);
  return Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(2 * i, 2 * i + 2), 16));
};

/** A field element (decimal or 0x-hex string) as its canonical 32-byte BE form. */
export function fieldBytes(value: string): Uint8Array {
  const v = BigInt(value);
  if (v < 0n || v >> 256n !== 0n) throw new Error(`field element out of range: ${value}`);
  return Uint8Array.from({ length: 32 }, (_, i) => Number((v >> BigInt(8 * (31 - i))) & 0xffn));
}

/**
 * The proof wire bytes from Groth16 calldata: a.x||a.y || b (the EVM/EIP-197
 * limb order snarkjs exportSolidityCallData already emits — imaginary limb
 * first, exactly the alt_bn128 syscall encoding) || c.x||c.y. Byte-identical
 * to the committed fixtures' `proof` (circuits/fixtures/fixture_lib.ts
 * proofHex is the same concatenation).
 */
export function proofBytes(calldata: Calldata): Uint8Array {
  const limbs = [
    calldata.a[0],
    calldata.a[1],
    calldata.b[0][0],
    calldata.b[0][1],
    calldata.b[1][0],
    calldata.b[1][1],
    calldata.c[0],
    calldata.c[1],
  ];
  const out = new Uint8Array(PROOF_LEN);
  for (const [i, limb] of limbs.entries()) out.set(fieldBytes(limb), 32 * i);
  return out;
}

/** One raw ML-KEM-768 ciphertext must be exactly KEM_CT_LEN bytes of 0x-hex —
 *  the program length-checks it (WrongKemCiphertextLength); checking here
 *  turns that on-chain reject into a readable client error (the EVM submit's
 *  belt, worn on this rail too). */
function kemCtBytes(ct: string, i: number): Uint8Array {
  const bytes = hexToBytes(ct);
  if (bytes.length !== KEM_CT_LEN) {
    throw new Error(`kemCiphertexts[${i}] must be ${KEM_CT_LEN} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * The complete instruction data for one consumer op: discriminator + proof +
 * the CARRIED publics (the table's derived `carried` index list applied to the
 * FULL calldata public vector — `enabled` never rides the wire, and withdraw's
 * `recipient` is bound from the accounts list) + the kem cts + the stealth
 * tail. Length is asserted against the table's wireLenOf — a drifted input
 * fails here, not as an on-chain length reject.
 */
export function encodeConsumerOpData(
  op: ConsumerOpName,
  calldata: Calldata,
  kemCiphertexts: string[],
  stealthTail: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const layout = SOLANA_OPS[op];
  if (calldata.pub.length !== layout.nPublic) {
    throw new Error(`${op}: expected ${layout.nPublic} public signals, got ${calldata.pub.length}`);
  }
  if (kemCiphertexts.length !== layout.kemCtCount) {
    throw new Error(`${op} carries ${layout.kemCtCount} kem ciphertexts, got ${kemCiphertexts.length}`);
  }
  if (stealthTail.length !== layout.stealthTailLen) {
    throw new Error(`${op}: stealth tail must be ${layout.stealthTailLen} bytes, got ${stealthTail.length}`);
  }
  const parts: Uint8Array[] = [
    Uint8Array.of(layout.discriminator),
    proofBytes(calldata),
    ...layout.carried.map((i) => fieldBytes(calldata.pub[i])),
    ...kemCiphertexts.map((ct, i) => kemCtBytes(ct, i)),
    stealthTail,
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  if (total !== wireLenOf(layout)) {
    throw new Error(`${op}: built ${total} wire bytes, layout table says ${wireLenOf(layout)}`);
  }
  const data = new Uint8Array(total);
  parts.reduce((off, p) => {
    data.set(p, off);
    return off + p.length;
  }, 0);
  return data;
}

/** Named FULL-publics reads off calldata via the layout table — the submit
 *  layer derives nullifiers/root/output commitments through these, never by a
 *  local index. Throws when the op's table has no such field. */
export function publicField(op: SolanaOpName, calldata: Calldata, field: string): bigint[] {
  const indices = SOLANA_OPS[op].fields[field];
  if (indices === undefined) throw new Error(`${op} has no public field "${field}"`);
  return indices.map((i) => BigInt(calldata.pub[i]));
}
