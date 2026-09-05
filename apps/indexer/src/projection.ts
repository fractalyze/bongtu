// Per-op feed projection (the revived descriptor table): the ONE pure mapping
// from decoded discovery material + resolved leaf indices to a FeedEntry
// draft, shared by both rail engines. Each rail keeps its own correlation
// machinery — EVM applyLogs: the takeAppend/takeOpApplied FIFO queues, the
// per-tx subtree/disclosure/ciphertext indexes, the WithdrawAnnouncement
// queue; Solana applyOne: op/event FIFO pairing, anchor cross-checks, the
// arbiter-epoch tripwire — and hands the CORRELATED result here, so
// cross-rail /events parity is true by construction instead of by two
// byte-parallel ladders.
//
// Parameterized divergences (the rails really do differ here, on purpose):
//   - `epoch` is an INPUT on the enterprise transfer family: the EVM caller
//     passes the event's epoch, the Solana caller passes its pinned
//     ARBITER_EPOCH_GENESIS (the rotation tripwire that guards that pin lives
//     in the Solana correlation, not here);
//   - `announcement` is an OPTIONAL input on the withdraw kinds: the Solana
//     rail decodes it inline from the instruction tail, while the EVM rail
//     attaches it AFTER addEvent by mutating the stored entry through its
//     per-tx WithdrawAnnouncement queue (that mechanism stays rail-side) —
//     an absent input leaves the key off the draft entirely;
//   - the enterprise `disburse` is EXCLUDED: the rails genuinely diverge
//     there (EVM bakes slices/ciphertext + the verifyDisclosure verdict into
//     the entry; Solana serves institution-held bytes with a registry verdict
//     and a rail-only disburseAnchor), so both branches stay in their rails.
//
// Everything else is table fact: which slices an op publishes, how its
// ciphertext run composes, and which optional fields ride the entry. The
// authority-tail slice length derives from the input array (uint256[16] on
// transfer, uint256[64] on transfer10, uint256[31] on transfer10x2, per the
// pool ABI — byte-identical to the former hard-codes), and viewTags
// normalize to decimal strings by the one rule both rails already served.

import type { FeedEntry, Slice } from "./store.js";
import type { DisclosureResult } from "./disclosure.js";

/** Chain position of the entry, rail-supplied: (txHash, blockNumber,
 *  logIndex) on EVM; (signature, slot, per-tx op ordinal) on Solana. */
export interface FeedPosition {
  txHash: string;
  blockNumber: number;
  logIndex: number;
}

/** The stealth discovery announcement of a withdraw kind — the store's own
 *  shape, aliased so the draft can never drift from what gets stored. */
export type AnnouncementDraft = NonNullable<FeedEntry["announcement"]>;

/**
 * One correlated op, ready to project — the table's input rows. Field
 * conventions: scalars/limbs arrive as bigints (the projection owns the
 * decimal-string normalization), kem ciphertexts arrive as 0x-hex strings
 * (normalized at each rail's decode edge), leaf indices are RESOLVED by the
 * rail's own correlation before they get here.
 */
export type OpProjection =
  // Enterprise deposit/withdraw: bare entries — the envelope bytes are
  // arbiter-ledger material and never join the PUBLIC feed entry on either
  // rail (SPEC §7 client-side-decrypt model).
  | { kind: "deposit" }
  | { kind: "withdraw"; announcement?: AnnouncementDraft }
  // Enterprise transfer family: receiver runs of 4 elements per output leaf,
  // then the authority envelope tail (not a leaf).
  | {
      kind: "transfer" | "transfer10" | "transfer10x2";
      epoch: number;
      ecdhPublicKey: [bigint, bigint];
      encryptionNonce: bigint;
      /** resolved output leaf indices, one per receiver slice, in ct order */
      outputLeafIndices: number[];
      /** the flat receiver ciphertext run (outputs x 4, leaf order) */
      receiverCts: bigint[];
      /** the authority envelope tail; its LENGTH is the tail slice's elts */
      authorityCt: bigint[];
    }
  // Consumer small ops (OPMOD §3.6), one arm for all three: two output
  // leaves, receiver cts ++ viewTags ++ per-output kem cts — and NOTHING for
  // a ledger (consumer ops carry no authority envelope by construction).
  | {
      kind: "depositPriv" | "transferPriv" | "transfer10x2Priv";
      ecdhPublicKey: [bigint, bigint];
      encryptionNonce: bigint;
      outputLeafIndices: [number, number];
      cts: bigint[];
      viewTags: bigint[];
      kemCiphertexts: string[];
    }
  // Consumer withdraw: one change leaf + the stealth announcement (optional
  // input — see the header on which rail passes it inline).
  | {
      kind: "withdrawPriv";
      ecdhPublicKey: [bigint, bigint];
      encryptionNonce: bigint;
      changeLeafIndex: number;
      cts: bigint[];
      viewTags: bigint[];
      kemCiphertexts: string[];
      announcement?: AnnouncementDraft;
    }
  // Consumer disburse (OPMOD §4): the 6B disclosure run [receiverCts 4B ++
  // viewTags B ++ outputCommitments B] projects to B slices + the optional
  // fields only when FULL; the verdict is computed rail-side (it needs the
  // subtreeRoot correlation) and rides through.
  | {
      kind: "disbursePriv";
      ecdhPublicKey: [bigint, bigint];
      encryptionNonce: bigint;
      startLeafIndex: number;
      batchSize: number;
      disclosure: bigint[];
      verdict: DisclosureResult;
    };

const dec = (x: bigint): string => x.toString();
const ecdhOf = (pk: [bigint, bigint]): [string, string] => [dec(pk[0]), dec(pk[1])];

/**
 * THE projection table: correlated op -> FeedEntry draft (everything but the
 * store-assigned seq). Pure and total over the projected kinds; a draft is
 * handed to store.addEvent by the rail, whose first-sight dedup and
 * nullifier bookkeeping stay rail-side.
 */
export function projectFeedEntry(at: FeedPosition, op: OpProjection): Omit<FeedEntry, "seq"> {
  const base = { txHash: at.txHash, blockNumber: at.blockNumber, logIndex: at.logIndex };
  switch (op.kind) {
    case "deposit":
      return {
        ...base, kind: "deposit", epoch: null,
        ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
      };
    case "withdraw":
      return {
        ...base, kind: "withdraw", epoch: null,
        ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
        ...(op.announcement !== undefined ? { announcement: op.announcement } : {}),
      };
    case "transfer":
    case "transfer10":
    case "transfer10x2": {
      // ciphertext layout: receivers[nOut][4] (flat, leaf order) ++ authority
      // tail; the tail slice's elts is the tail's own length (16 on transfer,
      // 64 on transfer10, 31 on transfer10x2, per the pool ABI).
      const slices: Slice[] = op.outputLeafIndices.map((leafIndex, i) => ({ offset: i * 4, elts: 4, leafIndex }));
      slices.push({ offset: 4 * op.outputLeafIndices.length, elts: op.authorityCt.length, leafIndex: null }); // authority envelope (not a leaf)
      return {
        ...base, kind: op.kind, epoch: op.epoch,
        ecdhPublicKey: ecdhOf(op.ecdhPublicKey), encryptionNonce: dec(op.encryptionNonce),
        slices, ciphertext: [...op.receiverCts, ...op.authorityCt].map(dec),
      };
    }
    case "depositPriv":
    case "transferPriv":
    case "transfer10x2Priv":
      return {
        ...base, kind: op.kind, epoch: null,
        ecdhPublicKey: ecdhOf(op.ecdhPublicKey), encryptionNonce: dec(op.encryptionNonce),
        slices: [
          { offset: 0, elts: 4, leafIndex: op.outputLeafIndices[0] },
          { offset: 4, elts: 4, leafIndex: op.outputLeafIndices[1] },
        ],
        ciphertext: op.cts.map(dec),
        viewTags: op.viewTags.map(dec),
        kemCiphertexts: [...op.kemCiphertexts],
      };
    case "withdrawPriv":
      return {
        ...base, kind: "withdrawPriv", epoch: null,
        ecdhPublicKey: ecdhOf(op.ecdhPublicKey), encryptionNonce: dec(op.encryptionNonce),
        slices: [{ offset: 0, elts: 4, leafIndex: op.changeLeafIndex }],
        ciphertext: op.cts.map(dec),
        viewTags: op.viewTags.map(dec),
        kemCiphertexts: [...op.kemCiphertexts],
        ...(op.announcement !== undefined ? { announcement: op.announcement } : {}),
      };
    case "disbursePriv": {
      const { startLeafIndex: start, batchSize: B, disclosure } = op;
      const full = disclosure.length === 6 * B;
      return {
        ...base, kind: "disbursePriv", epoch: null,
        ecdhPublicKey: ecdhOf(op.ecdhPublicKey), encryptionNonce: dec(op.encryptionNonce),
        slices: full
          ? Array.from({ length: B }, (_, i) => ({ offset: i * 4, elts: 4, leafIndex: start + i }))
          : [],
        ciphertext: disclosure.slice(0, 4 * B).map(dec),
        disclosure: op.verdict,
        ...(full
          ? {
              viewTags: disclosure.slice(4 * B, 5 * B).map(dec),
              outputCommitments: disclosure.slice(5 * B, 6 * B).map(dec),
            }
          : {}),
        batchId: start,
      };
    }
  }
}
