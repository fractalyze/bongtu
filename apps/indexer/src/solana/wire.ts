// Solana ledger wire decode (SOLR §3.2) — the pure translation layer under the
// Solana ingest backend. On this rail the discovery material rides in op
// INSTRUCTION DATA (the calldata analogue) and the per-op anchors ride
// SELF-CPI EVENTS (the log analogue, landing in a tx's inner instructions).
// The event decoders are byte-for-byte mirrors of event.rs; the OP layouts
// (discriminators, carried-publics composition, named field positions) come
// from the ONE layout table — @bongtu/core/solanaOps, the same table the
// vector generators consume, itself pinned against the Rust op modules and
// the committed conformance fixtures by packages/core/test/solana.test.ts —
// so no per-op index literal lives here.
//
// Everything is a pure function of bytes — the ingest backend (ingest.ts
// sibling) stays an I/O shell over these, which is what lets the conformance
// suite drive the whole backend from recorded ledger fixtures with no
// validator in the loop (SOLR §5.3).

import {
  ARBITER_EPOCH_GENESIS,
  EVENT_DISCRIMINATOR,
  KEM_CT_LEN,
  PROOF_LEN,
} from "@bongtu/core/solana";
import {
  SOLANA_OPS,
  familyTagOf,
  wireLenOf,
  type SolanaOpLayout,
} from "@bongtu/core/solanaOps";

// Rail fact re-exported for existing importers (the conformance leg): the
// one home is @bongtu/core/solana.
export { EVENT_DISCRIMINATOR };

/** One instruction as the ledger records it (top-level or inner). Pubkeys and
 *  data are 0x-hex — the recorded fixtures emit hex directly and the live RPC
 *  adapter (rpc.ts) converts base58 once at the edge, so ONE byte convention
 *  exists inside the indexer. */
export interface SolanaInstructionRecord {
  programId: string;
  data: string;
  /** account pubkeys in meta order. The live RPC adapter populates them for
   *  top-level AND inner instructions — a wrapper-invoked withdraw still
   *  reads meta 11 (its proof-bound recipient token account) — while recorded
   *  fixtures may omit them on records no decoder reads accounts from
   *  (self-CPI events, foreign CPIs), hence optional. */
  accounts?: string[];
}

/** One confirmed transaction touching the pool program, in ledger order. */
export interface SolanaLedgerTx {
  slot: number;
  blockTime: number;
  signature: string;
  instructions: SolanaInstructionRecord[];
  /** inner-instruction lists, parallel to `instructions` (CPIs in execution
   *  order — the self-CPI events live here, alongside foreign SPL/system
   *  CPIs the dispatch rule must skip). */
  inner: SolanaInstructionRecord[][];
}

export function bytesOfHex(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(h.length / 2);
  for (const i of Array(out.length).keys()) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function hexOfBytes(bytes: Uint8Array): string {
  return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const be32 = (bytes: Uint8Array, off: number): bigint => {
  return Array.from({ length: 32 }, (_, i) => bytes[off + i]).reduce<bigint>((acc, b) => (acc << 8n) | BigInt(b), 0n);
};

const le64 = (bytes: Uint8Array, off: number): number => {
  return Number(Array.from({ length: 8 }, (_, i) => bytes[off + i]).reduce<bigint>((acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)), 0n));
};

// --- self-CPI event decode (event.rs payload builders, byte-for-byte) -------

/** Family tag of the disburse anchor shape (event.rs: discriminator - 1,
 *  derived from the layout table, never retyped). */
export const FAMILY_DISBURSE256 = familyTagOf(SOLANA_OPS.disburse256);

/** The per-op anchor event (op_event_payload). */
export interface OpEventAnchor {
  shape: "op";
  family: number;
  startLeafIndex: number;
  leafCount: number;
  resultingRoot: bigint;
  nullifiers: bigint[];
}

/** The disburse anchor event (disburse_event_payload) — the same tuple the
 *  DisburseBatch PDA persists. */
export interface DisburseEventAnchor {
  shape: "disburse";
  family: number;
  startLeafIndex: number;
  subtreeRoot: bigint;
  resultingRoot: bigint;
  nullifier: bigint;
  disclosureHash: bigint;
  kemBinding: bigint;
  epoch: number;
}

export type SolanaEventAnchor = OpEventAnchor | DisburseEventAnchor;

export function decodeEvent(dataHex: string): SolanaEventAnchor {
  const d = bytesOfHex(dataHex);
  if (d[0] !== EVENT_DISCRIMINATOR) throw new Error("decodeEvent: not an event instruction");
  const family = d[1];
  if (family === FAMILY_DISBURSE256) {
    if (d.length !== 2 + 8 + 5 * 32 + 8) throw new Error(`decodeEvent: disburse event payload is ${d.length} bytes`);
    return {
      shape: "disburse",
      family,
      startLeafIndex: le64(d, 2),
      subtreeRoot: be32(d, 10),
      resultingRoot: be32(d, 42),
      nullifier: be32(d, 74),
      disclosureHash: be32(d, 106),
      kemBinding: be32(d, 138),
      epoch: le64(d, 170),
    };
  }
  const nfCount = d[43];
  if (d.length !== 44 + 32 * nfCount) throw new Error(`decodeEvent: op event payload is ${d.length} bytes for ${nfCount} nullifiers`);
  return {
    shape: "op",
    family,
    startLeafIndex: le64(d, 2),
    leafCount: d[10],
    resultingRoot: be32(d, 11),
    nullifiers: Array.from({ length: nfCount }, (_, i) => be32(d, 44 + 32 * i)),
  };
}

// --- op instruction decode ---------------------------------------------------

/** The stealth announcement tail of the two withdraw wires (33 B). */
export interface StealthTail {
  ephemeralPub: string; // 0x-hex 32 B
  viewTag: number;
}

interface OpBase {
  ecdhPublicKey: [bigint, bigint];
  encryptionNonce: bigint;
}

export type SolanaOpIx =
  | (OpBase & { kind: "depositPriv"; family: number; cts: bigint[]; viewTags: bigint[]; outputCommitments: [bigint, bigint]; kemCiphertexts: string[] })
  | (OpBase & { kind: "transferPriv"; family: number; cts: bigint[]; viewTags: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint]; kemCiphertexts: string[] })
  | (OpBase & { kind: "transfer10x2Priv"; family: number; cts: bigint[]; viewTags: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint]; kemCiphertexts: string[] })
  | (OpBase & { kind: "withdrawPriv"; family: number; cts: bigint[]; viewTags: bigint[]; nullifiers: bigint[]; changeCommitment: bigint; kemCiphertexts: string[]; stealth: StealthTail; recipientTokenAccount: string | null })
  | (OpBase & { kind: "deposit"; family: number; outputCommitments: [bigint, bigint] })
  | (OpBase & { kind: "withdraw"; family: number; nullifiers: bigint[]; changeCommitment: bigint; stealth: StealthTail; recipientTokenAccount: string | null })
  | (OpBase & { kind: "disburse"; family: number; disclosureHash: bigint; subtreeRoot: bigint; kemBinding: bigint; nullifier: bigint })
  | (OpBase & { kind: "transfer"; family: number; receiverCts: bigint[]; authorityCt: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint] })
  | (OpBase & { kind: "transfer10x2"; family: number; receiverCts: bigint[]; authorityCt: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint] });

/** FULL-publics-index reader over the carried run of `d` for layout `l`:
 *  wire position maps through the table's carried composition, so every
 *  field access below names FULL indices (the table's field map), never a
 *  local wire-position literal. Asking for an injected (non-carried) index
 *  is a decoder bug and throws. */
const fullReader = (d: Uint8Array, l: SolanaOpLayout): ((fullIndex: number) => bigint) => {
  const byFull = new Map<number, bigint>();
  for (const [w, fi] of l.carried.entries()) byFull.set(fi, be32(d, 1 + PROOF_LEN + 32 * w));
  return (i: number): bigint => {
    const v = byFull.get(i);
    if (v === undefined) throw new Error(`decodeOp: public ${i} is injected, not carried`);
    return v;
  };
};

const kemsOf = (d: Uint8Array, l: SolanaOpLayout): string[] => {
  const base = 1 + PROOF_LEN + 32 * l.carried.length;
  return Array.from({ length: l.kemCtCount }, (_, i) => hexOfBytes(d.subarray(base + i * KEM_CT_LEN, base + (i + 1) * KEM_CT_LEN)));
};

const stealthOf = (d: Uint8Array, l: SolanaOpLayout): StealthTail => {
  // The tail length is a table-owned fact (pinned to Rust STEALTH_TAIL_LEN):
  // 32-byte ephemeral pub + 1-byte view tag.
  const off = d.length - l.stealthTailLen;
  return { ephemeralPub: hexOfBytes(d.subarray(off, off + 32)), viewTag: d[off + 32] };
};

const pair = (f: (i: number) => bigint, idx: readonly number[]): [bigint, bigint] => [f(idx[0]), f(idx[1])];

const expectLen = (d: Uint8Array, want: number, kind: string): void => {
  if (d.length !== want) throw new Error(`decodeOp: ${kind} instruction is ${d.length} bytes, wire says ${want}`);
};

/**
 * Decode one pool op instruction. `accounts` is the instruction's meta list
 * (top-level or inner — a wrapper-invoked op carries the same layout) — only
 * the withdraw wires read it (the proof-bound recipient token account,
 * meta 11 in both withdraw layouts, feeds the announcement projection; an
 * accounts-table fact, not a publics-layout fact, so it stays here).
 * Field positions per @bongtu/core/solanaOps; `enabled` never rides the wire
 * (program-derived), so nothing here reconstructs it — the feed needs the
 * discovery material, not the verifier vector.
 */
export function decodeOp(dataHex: string, accounts?: string[]): SolanaOpIx | null {
  const d = bytesOfHex(dataHex);
  switch (d[0]) {
    case SOLANA_OPS.depositPriv.discriminator: {
      const l = SOLANA_OPS.depositPriv;
      expectLen(d, wireLenOf(l), "depositPriv");
      const f = fullReader(d, l);
      return {
        kind: "depositPriv", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        cts: l.fields.cts.map(f), viewTags: l.fields.viewTags.map(f),
        outputCommitments: pair(f, l.fields.outputCommitments), kemCiphertexts: kemsOf(d, l),
      };
    }
    case SOLANA_OPS.transferPriv.discriminator: {
      const l = SOLANA_OPS.transferPriv;
      expectLen(d, wireLenOf(l), "transferPriv");
      const f = fullReader(d, l);
      return {
        kind: "transferPriv", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        cts: l.fields.cts.map(f), viewTags: l.fields.viewTags.map(f), nullifiers: l.fields.nullifiers.map(f),
        outputCommitments: pair(f, l.fields.outputCommitments), kemCiphertexts: kemsOf(d, l),
      };
    }
    case SOLANA_OPS.transfer10x2Priv.discriminator: {
      const l = SOLANA_OPS.transfer10x2Priv;
      expectLen(d, wireLenOf(l), "transfer10x2Priv");
      const f = fullReader(d, l);
      return {
        kind: "transfer10x2Priv", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        cts: l.fields.cts.map(f), viewTags: l.fields.viewTags.map(f), nullifiers: l.fields.nullifiers.map(f),
        outputCommitments: pair(f, l.fields.outputCommitments), kemCiphertexts: kemsOf(d, l),
      };
    }
    case SOLANA_OPS.withdrawPriv.discriminator: {
      const l = SOLANA_OPS.withdrawPriv;
      expectLen(d, wireLenOf(l), "withdrawPriv");
      const f = fullReader(d, l);
      return {
        kind: "withdrawPriv", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        cts: l.fields.cts.map(f), viewTags: l.fields.viewTags.map(f), nullifiers: l.fields.nullifiers.map(f),
        changeCommitment: f(l.fields.changeCommitment[0]), kemCiphertexts: kemsOf(d, l), stealth: stealthOf(d, l),
        recipientTokenAccount: accounts?.[11] ?? null,
      };
    }
    case SOLANA_OPS.deposit.discriminator: {
      const l = SOLANA_OPS.deposit;
      expectLen(d, wireLenOf(l), "deposit");
      const f = fullReader(d, l);
      return {
        kind: "deposit", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        outputCommitments: pair(f, l.fields.outputCommitments),
      };
    }
    case SOLANA_OPS.withdraw.discriminator: {
      const l = SOLANA_OPS.withdraw;
      expectLen(d, wireLenOf(l), "withdraw");
      const f = fullReader(d, l);
      return {
        kind: "withdraw", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        nullifiers: l.fields.nullifiers.map(f), changeCommitment: f(l.fields.changeCommitment[0]),
        stealth: stealthOf(d, l), recipientTokenAccount: accounts?.[11] ?? null,
      };
    }
    case SOLANA_OPS.disburse256.discriminator: {
      const l = SOLANA_OPS.disburse256;
      expectLen(d, wireLenOf(l), "disburse256");
      const f = fullReader(d, l);
      return {
        kind: "disburse", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        disclosureHash: f(l.fields.disclosureHash[0]), subtreeRoot: f(l.fields.subtreeRoot[0]),
        kemBinding: f(l.fields.kemBinding[0]), nullifier: f(l.fields.nullifiers[0]),
      };
    }
    case SOLANA_OPS.transfer.discriminator: {
      const l = SOLANA_OPS.transfer;
      expectLen(d, wireLenOf(l), "transfer");
      const f = fullReader(d, l);
      return {
        kind: "transfer", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        receiverCts: l.fields.receiverCts.map(f), authorityCt: l.fields.authorityCt.map(f),
        nullifiers: l.fields.nullifiers.map(f), outputCommitments: pair(f, l.fields.outputCommitments),
      };
    }
    case SOLANA_OPS.transfer10x2.discriminator: {
      const l = SOLANA_OPS.transfer10x2;
      expectLen(d, wireLenOf(l), "transfer10x2");
      const f = fullReader(d, l);
      return {
        kind: "transfer10x2", family: familyTagOf(l),
        ecdhPublicKey: pair(f, l.fields.ecdhPublicKey), encryptionNonce: f(l.fields.encryptionNonce[0]),
        receiverCts: l.fields.receiverCts.map(f), authorityCt: l.fields.authorityCt.map(f),
        nullifiers: l.fields.nullifiers.map(f), outputCommitments: pair(f, l.fields.outputCommitments),
      };
    }
    default:
      // initialize / set_family_flags / a future family this build predates:
      // not discovery material. The stale-ABI posture does not apply — an
      // unknown discriminator still moves the TREE only through events this
      // decoder DOES know, so a genuinely new op family would fail the head
      // assert loudly rather than under-record silently.
      return null;
  }
}

/**
 * The dispatch walk (SOLR §3.2.2): every instruction of `tx` belonging to the
 * pool program — top-level AND inner (an op invoked through a wrapper program
 * must still be ours to ingest), in execution order, tagged with a per-tx
 * ordinal that plays the EVM logIndex role. Foreign-program instructions
 * (SPL escrow CPIs, system marker-PDA CPIs) fall out here — the dispatch rule
 * is program id + discriminator, never position.
 */
export function programInstructionsOf(
  tx: SolanaLedgerTx,
  programId: string,
): { data: string; accounts?: string[]; ordinal: number }[] {
  const pid = programId.toLowerCase();
  const out: { data: string; accounts?: string[]; ordinal: number }[] = [];
  for (const [i, ix] of tx.instructions.entries()) {
    if (ix.programId.toLowerCase() === pid) {
      out.push({ data: ix.data, accounts: ix.accounts, ordinal: out.length });
    }
    for (const inner of tx.inner[i] ?? []) {
      if (inner.programId.toLowerCase() === pid) {
        out.push({ data: inner.data, accounts: inner.accounts, ordinal: out.length });
      }
    }
  }
  return out;
}
