// Solana ledger wire decode (SOLR §3.2) — the pure translation layer under the
// Solana ingest backend. On this rail the discovery material rides in op
// INSTRUCTION DATA (the calldata analogue) and the per-op anchors ride
// SELF-CPI EVENTS (the log analogue, landing in a tx's inner instructions), so
// the decoders here are byte-for-byte mirrors of chains/solana/program/src
// (each op module's wire doc comment + event.rs). Layout constants are spelled
// per op instead of parsed from an IDL: the program is framework-free by
// design and the fixed offsets ARE its wire contract, gate-4-pinned.
//
// Everything is a pure function of bytes — the ingest backend (ingest.ts
// sibling) stays an I/O shell over these, which is what lets the conformance
// suite drive the whole backend from recorded ledger fixtures with no
// validator in the loop (SOLR §5.3).

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

export const EVENT_DISCRIMINATOR = 0xf0;

/** The program's default id (chains/solana/program declare_id!), as 0x-hex. */
export const DEFAULT_PROGRAM_ID_BASE58 = "HGVVfVfRnHauJoQwUttgUoy6ucG47LAXj8e6YBbZkoCj";

const PROOF_LEN = 256;
const KEM_CT_LEN = 1088;

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

/** Family tags (event.rs: instruction discriminator - 1). */
export const FAMILY_DISBURSE256 = 7;

/** Arbiter epoch on this rail, pinned at genesis (the Rust program's
 *  `state.rs ARBITER_EPOCH_GENESIS`; dated deviation in SOLR §3.3.1):
 *  `rotateArbiter` is not yet a Solana instruction, and the per-op event
 *  payload carries no epoch field, so ledger data cannot describe any other
 *  epoch. The ingest pins enterprise transfer feed entries to this value and
 *  trips loudly on the first disburse event that disproves the pin. */
export const ARBITER_EPOCH_GENESIS = 0;

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
  | (OpBase & { kind: "depositPriv"; family: 1; cts: bigint[]; viewTags: bigint[]; outputCommitments: [bigint, bigint]; kemCiphertexts: string[] })
  | (OpBase & { kind: "transferPriv"; family: 2; cts: bigint[]; viewTags: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint]; kemCiphertexts: string[] })
  | (OpBase & { kind: "transfer10x2Priv"; family: 3; cts: bigint[]; viewTags: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint]; kemCiphertexts: string[] })
  | (OpBase & { kind: "withdrawPriv"; family: 4; cts: bigint[]; viewTags: bigint[]; nullifiers: bigint[]; changeCommitment: bigint; kemCiphertexts: string[]; stealth: StealthTail; recipientTokenAccount: string | null })
  | (OpBase & { kind: "deposit"; family: 5; outputCommitments: [bigint, bigint] })
  | (OpBase & { kind: "withdraw"; family: 6; nullifiers: bigint[]; changeCommitment: bigint; stealth: StealthTail; recipientTokenAccount: string | null })
  | (OpBase & { kind: "disburse"; family: 7; disclosureHash: bigint; subtreeRoot: bigint; kemBinding: bigint; nullifier: bigint })
  | (OpBase & { kind: "transfer"; family: 8; receiverCts: bigint[]; authorityCt: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint] })
  | (OpBase & { kind: "transfer10x2"; family: 9; receiverCts: bigint[]; authorityCt: bigint[]; nullifiers: bigint[]; outputCommitments: [bigint, bigint] });

const carriedOf = (d: Uint8Array, n: number): bigint[] => {
  return Array.from({ length: n }, (_, i) => be32(d, 1 + PROOF_LEN + 32 * i));
};

const kemsOf = (d: Uint8Array, carried: number, count: number): string[] => {
  const base = 1 + PROOF_LEN + 32 * carried;
  return Array.from({ length: count }, (_, i) => hexOfBytes(d.subarray(base + i * KEM_CT_LEN, base + (i + 1) * KEM_CT_LEN)));
};

const stealthOf = (d: Uint8Array): StealthTail => {
  const off = d.length - 33;
  return { ephemeralPub: hexOfBytes(d.subarray(off, off + 32)), viewTag: d[off + 32] };
};

const expectLen = (d: Uint8Array, want: number, kind: string): void => {
  if (d.length !== want) throw new Error(`decodeOp: ${kind} instruction is ${d.length} bytes, wire says ${want}`);
};

/**
 * Decode one pool op instruction. `accounts` is the instruction's meta list
 * (top-level or inner — a wrapper-invoked op carries the same layout) — only
 * the withdraw wires read it (the proof-bound recipient token account,
 * meta 11 in both withdraw layouts, feeds the announcement projection).
 * Field positions per op module doc comment; `enabled` never rides the wire
 * (program-derived), so nothing here reconstructs it — the feed needs the
 * discovery material, not the verifier vector.
 */
export function decodeOp(dataHex: string, accounts?: string[]): SolanaOpIx | null {
  const d = bytesOfHex(dataHex);
  const disc = d[0];
  const wireLen = (carried: number, kems: number, tail = 0): number => 1 + PROOF_LEN + 32 * carried + kems * KEM_CT_LEN + tail;
  switch (disc) {
    case 2: {
      expectLen(d, wireLen(16, 2), "depositPriv");
      const c = carriedOf(d, 16);
      return {
        kind: "depositPriv", family: 1,
        ecdhPublicKey: [c[1], c[2]], encryptionNonce: c[15],
        cts: c.slice(3, 11), viewTags: [c[11], c[12]],
        outputCommitments: [c[13], c[14]], kemCiphertexts: kemsOf(d, 16, 2),
      };
    }
    case 3: {
      expectLen(d, wireLen(18, 2), "transferPriv");
      const c = carriedOf(d, 18);
      return {
        kind: "transferPriv", family: 2,
        ecdhPublicKey: [c[0], c[1]], encryptionNonce: c[17],
        cts: c.slice(2, 10), viewTags: [c[10], c[11]], nullifiers: [c[12], c[13]],
        outputCommitments: [c[15], c[16]], kemCiphertexts: kemsOf(d, 18, 2),
      };
    }
    case 4: {
      expectLen(d, wireLen(26, 2), "transfer10x2Priv");
      const c = carriedOf(d, 26);
      return {
        kind: "transfer10x2Priv", family: 3,
        ecdhPublicKey: [c[0], c[1]], encryptionNonce: c[25],
        cts: c.slice(2, 10), viewTags: [c[10], c[11]], nullifiers: c.slice(12, 22),
        outputCommitments: [c[23], c[24]], kemCiphertexts: kemsOf(d, 26, 2),
      };
    }
    case 5: {
      expectLen(d, wireLen(13, 1, 33), "withdrawPriv");
      const c = carriedOf(d, 13);
      return {
        kind: "withdrawPriv", family: 4,
        ecdhPublicKey: [c[1], c[2]], encryptionNonce: c[12],
        cts: c.slice(3, 7), viewTags: [c[7]], nullifiers: [c[8], c[9]],
        changeCommitment: c[11], kemCiphertexts: kemsOf(d, 13, 1), stealth: stealthOf(d),
        recipientTokenAccount: accounts?.[11] ?? null,
      };
    }
    case 6: {
      expectLen(d, wireLen(17, 1), "deposit");
      const c = carriedOf(d, 17);
      return {
        kind: "deposit", family: 5,
        ecdhPublicKey: [c[1], c[2]], encryptionNonce: c[16],
        outputCommitments: [c[14], c[15]],
      };
    }
    case 7: {
      expectLen(d, wireLen(22, 1, 33), "withdraw");
      const c = carriedOf(d, 22);
      return {
        kind: "withdraw", family: 6,
        ecdhPublicKey: [c[1], c[2]], encryptionNonce: c[21],
        nullifiers: [c[17], c[18]], changeCommitment: c[20], stealth: stealthOf(d),
        recipientTokenAccount: accounts?.[11] ?? null,
      };
    }
    case 8: {
      expectLen(d, wireLen(8, 1), "disburse256");
      const c = carriedOf(d, 8);
      return {
        kind: "disburse", family: 7,
        ecdhPublicKey: [c[0], c[1]], encryptionNonce: c[7],
        disclosureHash: c[2], subtreeRoot: c[3], kemBinding: c[4], nullifier: c[5],
      };
    }
    case 9: {
      expectLen(d, wireLen(33, 1), "transfer");
      const c = carriedOf(d, 33);
      return {
        kind: "transfer", family: 8,
        ecdhPublicKey: [c[0], c[1]], encryptionNonce: c[32],
        receiverCts: c.slice(2, 10), authorityCt: c.slice(10, 26),
        nullifiers: [c[27], c[28]], outputCommitments: [c[30], c[31]],
      };
    }
    case 10: {
      expectLen(d, wireLen(56, 1), "transfer10x2");
      const c = carriedOf(d, 56);
      return {
        kind: "transfer10x2", family: 9,
        ecdhPublicKey: [c[0], c[1]], encryptionNonce: c[55],
        receiverCts: c.slice(2, 10), authorityCt: c.slice(10, 41),
        nullifiers: c.slice(42, 52), outputCommitments: [c[53], c[54]],
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
