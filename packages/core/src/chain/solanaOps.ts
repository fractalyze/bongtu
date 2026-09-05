// One TypeScript owner for the per-op public-signal layouts of the Solana
// rail (SOLR §2.3 / §3.1.2 "no derivable publics" wire): the vector
// generators (chains/solana/scripts/gen_*.ts) and the indexer's ledger
// decoder (apps/indexer/src/solana/wire.ts) both consume THIS table, and the
// future client-solana instruction encoder is its third consumer. The Rust
// reconstruction (chains/solana/program/src/<op>.rs) stays hand-written on
// purpose — checker and checked must not collapse (the same reasoning that
// keeps circuits/auditor_decrypt_check.ts hand-decoded).
//
// Faithfulness is gated twice: packages/core/test/solana.test.ts pins every
// row against the Rust op constants (parsed as text) AND against the
// committed conformance fixtures (chains/solana/conformance/*_fixture.json
// publicsFull/publicsCarried), and the vectorsByteIdentical gate requires
// regenerating those fixtures from this table byte-for-byte.
//
// Wire shape per op, after the 1-byte instruction discriminator:
//   proof(PROOF_LEN) || carried publics (32 B BE each) ||
//   kemCtCount × KEM_CT_LEN || stealthTailLen bytes
// Carried publics are the FULL circuit public vector minus the
// program-INJECTED signals — `enabled` (reconstructed as nullifier != 0),
// `authorityPubKey` (config-injected, enterprise family), and `recipient`
// (bound from the accounts list, the withdraw wires) — so `carried` is
// DERIVED from the field map below, never retyped, exactly as the family
// tag (discriminator - 1) and the state.rs enable flag (1 << (tag - 1)) are.

import { KEM_CT_LEN, PROOF_LEN } from "./solana.js";

/** `enabled` derivation over FULL publics indices: pub[enabledAt + i] ==
 *  (pub[nullifiersAt + i] != 0 ? 1 : 0) for i < arity. `constantOne` marks
 *  disburse256, whose sole input is guaranteed real (the ZeroNullifier
 *  guard), so the program injects an unconditional 1. */
export interface SolanaEnabledSpec {
  readonly nullifiersAt: number;
  readonly enabledAt: number;
  readonly arity: number;
  readonly constantOne: boolean;
}

export interface SolanaOpLayout {
  /** 1-byte instruction discriminator (lib.rs dispatch; op DISCRIMINATOR). */
  readonly discriminator: number;
  /** FULL circuit public vector length (op N_PUBLIC). */
  readonly nPublic: number;
  /** Trailing raw ML-KEM-768 ciphertexts on the wire (op KEM_CT_COUNT). */
  readonly kemCtCount: number;
  /** 0, or 33 (32 B stealth ephemeral pub + 1 B view tag) on the two
   *  withdraw wires (op STEALTH_TAIL_LEN). */
  readonly stealthTailLen: number;
  /** Named fields over FULL publics indices; together they cover the vector
   *  exactly once (the test asserts the permutation). */
  readonly fields: Readonly<Record<string, readonly number[]>>;
  /** FULL indices that ride the wire, in wire order — derived: everything
   *  minus enabled/authorityPubKey/recipient (op CARRIED_PUBLICS pins the
   *  length; publicsCarried in the fixtures pins the composition). */
  readonly carried: readonly number[];
  readonly enabled: SolanaEnabledSpec | null;
}

/** [start, end) index run. */
const seq = (start: number, end: number): number[] =>
  Array.from({ length: end - start }, (_, i) => start + i);

interface OpSpec<F extends Record<string, readonly number[]>> {
  discriminator: number;
  nPublic: number;
  kemCtCount: number;
  stealthTailLen?: number;
  enabledConstantOne?: boolean;
  fields: F;
}

const defineOp = <F extends Record<string, readonly number[]>>(
  spec: OpSpec<F>,
): SolanaOpLayout & { readonly fields: F } => {
  const f: Partial<Record<string, readonly number[]>> = spec.fields;
  const injected = new Set([
    ...(f.enabled ?? []),
    ...(f.authorityPubKey ?? []),
    ...(f.recipient ?? []),
  ]);
  const enabled =
    f.enabled === undefined || f.nullifiers === undefined
      ? null
      : {
          nullifiersAt: f.nullifiers[0],
          enabledAt: f.enabled[0],
          arity: f.nullifiers.length,
          constantOne: spec.enabledConstantOne === true,
        };
  return {
    discriminator: spec.discriminator,
    nPublic: spec.nPublic,
    kemCtCount: spec.kemCtCount,
    stealthTailLen: spec.stealthTailLen ?? 0,
    fields: spec.fields,
    carried: seq(0, spec.nPublic).filter((i) => !injected.has(i)),
    enabled,
  };
};

export const SOLANA_OPS = {
  // --- consumer (no-auditor P2P) family ------------------------------------
  depositPriv: defineOp({
    discriminator: 2,
    nPublic: 16,
    kemCtCount: 2,
    fields: {
      amount: [0],
      ecdhPublicKey: [1, 2],
      cts: seq(3, 11),
      viewTags: [11, 12],
      outputCommitments: [13, 14],
      encryptionNonce: [15],
    },
  }),
  transferPriv: defineOp({
    discriminator: 3,
    nPublic: 20,
    kemCtCount: 2,
    fields: {
      ecdhPublicKey: [0, 1],
      cts: seq(2, 10),
      viewTags: [10, 11],
      nullifiers: [12, 13],
      root: [14],
      enabled: [15, 16],
      outputCommitments: [17, 18],
      encryptionNonce: [19],
    },
  }),
  transfer10x2Priv: defineOp({
    discriminator: 4,
    nPublic: 36,
    kemCtCount: 2,
    fields: {
      ecdhPublicKey: [0, 1],
      cts: seq(2, 10),
      viewTags: [10, 11],
      nullifiers: seq(12, 22),
      root: [22],
      enabled: seq(23, 33),
      outputCommitments: [33, 34],
      encryptionNonce: [35],
    },
  }),
  withdrawPriv: defineOp({
    discriminator: 5,
    nPublic: 16,
    kemCtCount: 1,
    stealthTailLen: 33,
    fields: {
      amount: [0],
      ecdhPublicKey: [1, 2],
      cts: seq(3, 7),
      viewTags: [7],
      nullifiers: [8, 9],
      root: [10],
      enabled: [11, 12],
      changeCommitment: [13],
      encryptionNonce: [14],
      recipient: [15],
    },
  }),
  // --- enterprise (arbiter-enveloped) family --------------------------------
  deposit: defineOp({
    discriminator: 6,
    nPublic: 19,
    kemCtCount: 1,
    fields: {
      amount: [0],
      ecdhPublicKey: [1, 2],
      authorityCt: seq(3, 13),
      kemBinding: [13],
      outputCommitments: [14, 15],
      encryptionNonce: [16],
      authorityPubKey: [17, 18],
    },
  }),
  withdraw: defineOp({
    discriminator: 7,
    nPublic: 27,
    kemCtCount: 1,
    stealthTailLen: 33,
    fields: {
      amount: [0],
      ecdhPublicKey: [1, 2],
      authorityCt: seq(3, 16),
      kemBinding: [16],
      nullifiers: [17, 18],
      root: [19],
      enabled: [20, 21],
      changeCommitment: [22],
      encryptionNonce: [23],
      authorityPubKey: [24, 25],
      recipient: [26],
    },
  }),
  disburse256: defineOp({
    discriminator: 8,
    nPublic: 11,
    kemCtCount: 1,
    enabledConstantOne: true,
    fields: {
      ecdhPublicKey: [0, 1],
      disclosureHash: [2],
      subtreeRoot: [3],
      kemBinding: [4],
      nullifiers: [5],
      root: [6],
      enabled: [7],
      encryptionNonce: [8],
      authorityPubKey: [9, 10],
    },
  }),
  transfer: defineOp({
    discriminator: 9,
    nPublic: 37,
    kemCtCount: 1,
    fields: {
      ecdhPublicKey: [0, 1],
      receiverCts: seq(2, 10),
      authorityCt: seq(10, 26),
      kemBinding: [26],
      nullifiers: [27, 28],
      root: [29],
      enabled: [30, 31],
      outputCommitments: [32, 33],
      encryptionNonce: [34],
      authorityPubKey: [35, 36],
    },
  }),
  transfer10x2: defineOp({
    discriminator: 10,
    nPublic: 68,
    kemCtCount: 1,
    fields: {
      ecdhPublicKey: [0, 1],
      receiverCts: seq(2, 10),
      authorityCt: seq(10, 41),
      kemBinding: [41],
      nullifiers: seq(42, 52),
      root: [52],
      enabled: seq(53, 63),
      outputCommitments: [63, 64],
      encryptionNonce: [65],
      authorityPubKey: [66, 67],
    },
  }),
} as const;

export type SolanaOpName = keyof typeof SOLANA_OPS;

/** Event/op-provenance family tag (event.rs FAMILY_TAG_*): instruction
 *  discriminator - 1, DERIVED, never retyped. */
export const familyTagOf = (l: SolanaOpLayout): number => l.discriminator - 1;

/** state.rs family-enable flag (the module-registry analogue): the bit
 *  assignment is 1 << (familyTag - 1) by construction. */
export const familyFlagOf = (l: SolanaOpLayout): number => 1 << (familyTagOf(l) - 1);

/** Full instruction wire length, INCLUDING the 1-byte discriminator (the
 *  Rust PAYLOAD_LEN is this minus 1). */
export const wireLenOf = (l: SolanaOpLayout): number =>
  1 + PROOF_LEN + 32 * l.carried.length + l.kemCtCount * KEM_CT_LEN + l.stealthTailLen;
