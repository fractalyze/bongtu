// Arbiter-mode note ledger (SPEC §6b v2 enforced auditor disclosure).
//
// Built ONLY when the indexer holds the arbiter PRIVATE key (AUTHORITY_KEY set).
// For every op, in chain order, it decrypts the op's authority envelope
// (@bongtu/core/envelope — the owning codec) and:
//
//   - OUTPUT notes become ledger entries keyed by owner pubkey (value, salt,
//     leafIndex, txHash, commitment, spent=false), AFTER cross-checking each
//     recovered note's commitment == the on-chain output commitment the indexer
//     already knows: deposit oc0/oc1, transfer outputs, withdraw change, and for
//     disburse the B leaves folded to the on-chain subtreeRoot. A mismatch is a
//     first-class ALARM (console + the GET /alarms feed, via getEnvelopeAlarms),
//     never silently kept.
//
//   - INPUT notes mark the matching created note spent, matched by commitment.
//     The input envelope reveals the consumed note's (owner, value, salt), so
//     spent status comes from envelopes ALONE — no owner private key and no
//     nullifier linkage needed (this is strictly MORE complete than nullifier
//     matching, which only reveals *that* something was spent, not which note).
//
//   - a disburse's B recovered commitments are handed to MirrorTree.fillBatch so
//     arbiter-mode GET /path can serve a real path INTO the batch (public mode,
//     which never fills, keeps returning the 422 batch-leaf sentinel, §11-7).
//
//   - the SAME decrypted envelope also yields a per-owner ACTIVITY HISTORY
//     (GET /history): received / sent / withdraw / deposit items with the
//     counterparty + amount that op meant for each owner.
//
// TWO-ADAPTER SEAM (U-I2). The decrypt/derive step — envelope → (output notes,
// spent-marks, cross-check alarms, batch fill, history) — is ONE shared PURE
// function `deriveOp`, holding ALL of the crypto (parseEnvelope, commitment fold,
// subtree cross-check, history derivation). Only the RECORD/READ half differs per
// backend: `InMemoryLedger` keeps byOwner/byCommitment/historyByOwner/applied maps
// in process; `PostgresLedger` (src/postgres.ts) keeps the same maps as a boot-
// hydrated read model AND persists each derived op to SQL. Both call `deriveOp`
// exactly once per op — the crypto is never duplicated.
//
// The arbiter private key lives in the adapter object and is NEVER serialized into
// any HTTP response or log line — only recovered note fields (which are exactly
// what the auditor is entitled to see) ever leave here.

import type { PoolClient } from "pg";
import { commitment as noteCommitment } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { packPubkey } from "@bongtu/core/pubkey";
import type { Point } from "@bongtu/core/babyjub";
import type { MirrorTree } from "./tree.js";
import { parseEnvelope, type OpKind, type ParsedEnvelope } from "@bongtu/core/envelope";

const dec = (x: bigint): string => x.toString();

/** A ledger note, exactly as served by GET /notes (no private key, ever). */
export interface LedgerNote {
  owner: [string, string]; // decimal bjj pubkey
  value: string; // decimal
  salt: string; // decimal
  leafIndex: number;
  commitment: string; // decimal
  txHash: string;
  spent: boolean;
}

/** An envelope cross-check failure: a recovered commitment != the on-chain one. */
export interface EnvelopeAlarm {
  kind: OpKind;
  txHash: string;
  detail: string;
  recomputed: string; // decimal
  expected: string; // decimal
}

/** The kind of a per-owner activity item, as served by GET /history. */
export type HistoryKind = "received" | "sent" | "withdraw" | "deposit";

/**
 * One entry of an owner's activity history (GET /history) — derived from the
 * decrypted authority envelopes the ledger already holds, no re-decrypt:
 *   - "received": an output note addressed to the owner by another party
 *     (counterparty = the op's input owner: employer for a disburse, sender for
 *     a transfer);
 *   - "sent":     a transfer whose spent input was the owner's (counterparty =
 *     the payee, amount = what left them);
 *   - "withdraw": the owner unshielded (counterparty null, amount = unshielded);
 *   - "deposit":  the owner's own deposit output (counterparty null).
 * `counterparty` is a COMPRESSED bjj pubkey hex (never a raw x,y pair). Wire shape
 * owned by @bongtu/core/indexerApi (HistoryItem) — this stays structurally equal.
 */
export interface LedgerHistoryItem {
  kind: HistoryKind;
  counterparty: string | null; // compressed bjj pubkey hex, or null
  amount: string; // decimal
  txHash: string;
  blockTimestamp: number; // unix seconds
  seq: number; // monotonic in chain-apply order; history is sorted by seq desc
}

/**
 * What ingest hands the ledger per op — all PUBLIC chain data plus the authority
 * ciphertext. `outputLeaves` are the on-chain output commitments the recovered
 * outputs must reproduce (deposit/transfer: the two appended leaves; withdraw:
 * the change leaf; disburse: empty — the batch cross-check uses `batch` instead).
 */
export interface OpEnvelope {
  kind: OpKind;
  txHash: string;
  logIndex: number; // chain position of the op's log — the ledger's replay-dedup key
  blockTimestamp: number; // unix seconds of the op's block — stamped onto history items
  ecdhPublicKey: [bigint, bigint];
  nonce: bigint;
  authorityCt: bigint[]; // authority envelope ciphertext (disburse: the tail only)
  outputLeaves: { leafIndex: number; commitment: bigint }[];
  batch?: { startLeafIndex: number; subtreeRoot: bigint }; // disburse only
}

/** The read/write surface both ledger adapters expose (U-I2 two-adapter seam). */
export interface LedgerPort {
  /** Ingest one op's envelope in chain order (idempotent on (txHash, logIndex)). */
  apply(op: OpEnvelope): void;
  /** Every note owned by (x,y) — the arbiter's authoritative view of that owner. */
  notesOf(ownerX: bigint, ownerY: bigint): LedgerNote[];
  /** One owner's activity history, newest-first (seq desc). */
  historyOf(ownerX: bigint, ownerY: bigint): LedgerHistoryItem[];
  /** Envelope cross-check failures surfaced during ingest (auditor-console feed). */
  getEnvelopeAlarms(): EnvelopeAlarm[];
  /** Stage the notes/history/alarms/applied-ops buffered by apply() into the
   *  indexer's open txn (Postgres only; in-memory omits it, a no-op). */
  flushInto?(client: PoolClient): Promise<void>;
  /** Drop those buffers AFTER the indexer's COMMIT (Postgres only). */
  commitFlush?(): void;
}

// ---------------------------------------------------------------------------
// Shared PURE derive — ALL the crypto lives here, both adapters call it once.
// ---------------------------------------------------------------------------

/** An output note the op created, recovered + cross-checked (spent starts false). */
export interface DerivedNote {
  owner: Point;
  value: bigint;
  salt: bigint;
  leafIndex: number;
  commitment: bigint;
}

/** A per-owner activity draft — seq is assigned by the recording adapter. */
export interface DerivedHistory {
  owner: Point;
  kind: HistoryKind;
  counterparty: Point | null;
  amount: bigint;
}

/** Everything one op derives from its envelope — pure of any storage backend. */
export interface DerivedOp {
  outputs: DerivedNote[]; // notes to record (spent=false)
  spent: bigint[]; // input commitments to mark spent (a no-op if unknown)
  alarms: EnvelopeAlarm[]; // envelope cross-check failures
  batchFill: { start: number; leaves: bigint[] } | null; // set iff the disburse batch folds to its on-chain subtreeRoot
  history: DerivedHistory[]; // activity drafts (recorded in chain-apply order)
}

const sameOwner = (a: Point, b: Point): boolean => a[0] === b[0] && a[1] === b[1];

/**
 * Decrypt + verify + derive one op (the WHOLE crypto step of the ledger). Returns
 * the output notes to record, the input commitments to mark spent, any cross-check
 * alarms, a batch-fill instruction (a cross-checked disburse only), and the
 * activity history — all as plain data an adapter records however it likes. Pure:
 * it reads nothing but its arguments (the tree height is passed in), writes nothing.
 */
export function deriveOp(arbiterPriv: bigint, B: number, treeH: number, op: OpEnvelope): DerivedOp {
  const env = parseEnvelope(arbiterPriv, op.ecdhPublicKey, op.nonce, op.authorityCt, op.kind, B);
  const outputs: DerivedNote[] = [];
  const alarms: EnvelopeAlarm[] = [];
  let batchFill: { start: number; leaves: bigint[] } | null = null;
  let disburseCrossChecks = false;

  if (op.kind === "disburse") {
    // Cross-check: fold the B recovered commitments to a subtree root and compare
    // to the on-chain subtreeRoot. On match, record the notes and mark the batch
    // fillable; a mismatch is an ALARM and the batch stays unopened.
    const start = op.batch!.startLeafIndex;
    const commits = env.outputs.map((o) => noteCommitment(o.value, o.salt, o.owner));
    const sub = new ImtTree(treeH, B).computeSubtreeRoot(commits);
    if (sub !== op.batch!.subtreeRoot) {
      alarms.push({
        kind: op.kind,
        txHash: op.txHash,
        detail: `disburse batch @${start}: envelope leaves fold != on-chain subtreeRoot`,
        recomputed: dec(sub),
        expected: dec(op.batch!.subtreeRoot),
      });
    } else {
      for (let i = 0; i < B; i++) {
        const o = env.outputs[i];
        outputs.push({ owner: o.owner, value: o.value, salt: o.salt, leafIndex: start + i, commitment: commits[i] });
      }
      batchFill = { start, leaves: commits };
      disburseCrossChecks = true;
    }
  } else {
    // deposit / transfer / withdraw: each recovered output must reproduce a known
    // on-chain leaf commitment, in order.
    for (let i = 0; i < op.outputLeaves.length; i++) {
      const o = env.outputs[i];
      const c = noteCommitment(o.value, o.salt, o.owner);
      const known = op.outputLeaves[i];
      if (c !== known.commitment) {
        alarms.push({
          kind: op.kind,
          txHash: op.txHash,
          detail: `output#${i} @${known.leafIndex}: envelope commitment != on-chain leaf`,
          recomputed: dec(c),
          expected: dec(known.commitment),
        });
        continue; // do not record an unverifiable note
      }
      outputs.push({ owner: o.owner, value: o.value, salt: o.salt, leafIndex: known.leafIndex, commitment: c });
    }
  }

  // INPUT notes: the consumed note's commitment is recovered from the envelope; the
  // recording adapter marks the matching created note spent (a padded/disabled
  // input has no matching note, so it is a harmless no-op there).
  const spent = env.inputs.map((inp) => noteCommitment(inp.value, inp.salt, inp.owner));

  return { outputs, spent, alarms, batchFill, history: deriveHistory(op, env, disburseCrossChecks) };
}

/**
 * Per-owner activity drafts from the op's decrypted envelope (no re-decrypt — `env`
 * is what the notes were built from). Zero-value notes (pads, residues, zero
 * change) contribute nothing. Semantics per SPEC §6b / LedgerHistoryItem:
 *   - deposit:  each of the depositor's own outputs → "deposit".
 *   - transfer: the input owner is the sender; each non-self output → a "received"
 *     for its owner (counterparty = sender) AND a matching "sent" for the sender
 *     (counterparty = that payee). Both outputs can be independent payees, so a
 *     split payment yields two "sent" items, never one merged item. A self output
 *     is the sender's change and is NOT listed.
 *   - disburse: each non-self output → "received" (counterparty = the employer
 *     input owner). Only a cross-checked batch contributes.
 *   - withdraw: the input owner unshielded inputs − change → "withdraw".
 */
function deriveHistory(op: OpEnvelope, env: ParsedEnvelope, disburseCrossChecks: boolean): DerivedHistory[] {
  const out: DerivedHistory[] = [];
  switch (op.kind) {
    case "deposit":
      for (const o of env.outputs) {
        if (o.value !== 0n) out.push({ owner: o.owner, kind: "deposit", counterparty: null, amount: o.value });
      }
      return out;
    case "disburse": {
      if (!disburseCrossChecks) return out;
      const sender = env.inputs[0].owner;
      for (const o of env.outputs) {
        if (o.value !== 0n && !sameOwner(o.owner, sender)) {
          out.push({ owner: o.owner, kind: "received", counterparty: sender, amount: o.value });
        }
      }
      return out;
    }
    case "transfer": {
      // transfer is 2-out with INDEPENDENT output owners, so both outputs can be
      // distinct non-self payees: emit one "received" AND one matching "sent" per
      // non-self output — never collapse a split payment into a single item.
      const sender = env.inputs[0].owner;
      for (const o of env.outputs) {
        if (o.value !== 0n && !sameOwner(o.owner, sender)) {
          out.push({ owner: o.owner, kind: "received", counterparty: sender, amount: o.value });
          out.push({ owner: sender, kind: "sent", counterparty: o.owner, amount: o.value });
        }
      }
      return out;
    }
    case "withdraw": {
      const owner = env.inputs[0].owner;
      const inSum = env.inputs.reduce((a, i) => a + i.value, 0n);
      const change = env.outputs.reduce((a, o) => a + o.value, 0n);
      const withdrawn = inSum - change;
      if (withdrawn > 0n) out.push({ owner, kind: "withdraw", counterparty: null, amount: withdrawn });
      return out;
    }
  }
}

// ---------------------------------------------------------------------------
// Shared RECORD helpers — the small map/console ops both adapters reuse (no
// crypto). Kept as free functions so InMemoryLedger and PostgresLedger own their
// OWN maps (the per-adapter difference) without re-implementing the bookkeeping.
// ---------------------------------------------------------------------------

/** The byOwner / historyByOwner map key for an owner pubkey. */
export function ownerKey(x: bigint, y: bigint): string {
  return `${x},${y}`;
}

/** Turn a derived output into a stored LedgerNote and index it in both maps. */
export function recordNote(
  byOwner: Map<string, LedgerNote[]>,
  byCommitment: Map<string, LedgerNote>,
  o: DerivedNote,
  txHash: string,
): LedgerNote {
  const note: LedgerNote = {
    owner: [dec(o.owner[0]), dec(o.owner[1])],
    value: dec(o.value),
    salt: dec(o.salt),
    leafIndex: o.leafIndex,
    commitment: dec(o.commitment),
    txHash,
    spent: false,
  };
  const k = ownerKey(o.owner[0], o.owner[1]);
  const arr = byOwner.get(k) ?? [];
  arr.push(note);
  byOwner.set(k, arr);
  byCommitment.set(note.commitment, note);
  return note;
}

/** Turn a history draft + assigned seq into a stored LedgerHistoryItem. */
export function makeHistoryItem(draft: DerivedHistory, op: OpEnvelope, seq: number): LedgerHistoryItem {
  return {
    kind: draft.kind,
    counterparty: draft.counterparty ? packPubkey(draft.counterparty) : null,
    amount: dec(draft.amount),
    txHash: op.txHash,
    blockTimestamp: op.blockTimestamp,
    seq,
  };
}

/** Append a history item to its owner's list. */
export function pushHistory(historyByOwner: Map<string, LedgerHistoryItem[]>, owner: Point, item: LedgerHistoryItem): void {
  const k = ownerKey(owner[0], owner[1]);
  const arr = historyByOwner.get(k) ?? [];
  arr.push(item);
  historyByOwner.set(k, arr);
}

/** The auditor-console line for an envelope cross-check failure. */
export function logEnvelopeAlarm(a: EnvelopeAlarm): void {
  console.error(`ALARM envelope ${a.kind} tx=${a.txHash} ${a.detail} recomputed=${a.recomputed} expected=${a.expected}`);
}

// ---------------------------------------------------------------------------
// In-memory adapter — the original ledger, re-derived from chain on every start.
// ---------------------------------------------------------------------------

export class InMemoryLedger implements LedgerPort {
  private readonly arbiterPriv: bigint; // NEVER leaves this object
  private readonly B: number;
  private readonly tree: MirrorTree;
  private readonly byOwner = new Map<string, LedgerNote[]>();
  private readonly byCommitment = new Map<string, LedgerNote>();
  private readonly alarms: EnvelopeAlarm[] = [];
  private readonly historyByOwner = new Map<string, LedgerHistoryItem[]>();
  private historySeq = 0;
  // (txHash, logIndex) of every op already applied — the ledger guards its OWN
  // replay invariant (the same self-guarding pattern as MirrorTree / Store), so a
  // replayed log range cannot double-record notes or re-flip spent flags.
  private readonly applied = new Set<string>();

  constructor(arbiterPriv: bigint, B: number, tree: MirrorTree) {
    this.arbiterPriv = arbiterPriv;
    this.B = B;
    this.tree = tree;
  }

  /**
   * Ingest one op's envelope in chain order: verify + record outputs, mark inputs
   * spent, and (disburse) fill the batch leaves so /path can serve into it.
   * Replay-safe: idempotent on (txHash, logIndex).
   */
  apply(op: OpEnvelope): void {
    const key = `${op.txHash}:${op.logIndex}`;
    if (this.applied.has(key)) return; // replayed op — already recorded
    this.applied.add(key);

    const d = deriveOp(this.arbiterPriv, this.B, this.tree.H, op);
    for (const o of d.outputs) recordNote(this.byOwner, this.byCommitment, o, op.txHash);
    for (const a of d.alarms) {
      this.alarms.push(a);
      logEnvelopeAlarm(a);
    }
    if (d.batchFill) this.tree.fillBatch(d.batchFill.start, d.batchFill.leaves);
    for (const c of d.spent) {
      const note = this.byCommitment.get(dec(c));
      if (note) note.spent = true;
    }
    for (const h of d.history) pushHistory(this.historyByOwner, h.owner, makeHistoryItem(h, op, this.historySeq++));
  }

  notesOf(ownerX: bigint, ownerY: bigint): LedgerNote[] {
    return this.byOwner.get(ownerKey(ownerX, ownerY)) ?? [];
  }

  historyOf(ownerX: bigint, ownerY: bigint): LedgerHistoryItem[] {
    const arr = this.historyByOwner.get(ownerKey(ownerX, ownerY)) ?? [];
    return [...arr].sort((a, b) => b.seq - a.seq);
  }

  getEnvelopeAlarms(): EnvelopeAlarm[] {
    return this.alarms;
  }
}

// Back-compat alias: the anvil-free ingest unit test constructs `new NoteLedger(…)`
// directly (an intentionally-untouched test), and the name still reads true — the
// in-memory ledger IS the note ledger. Postgres mode uses PostgresLedger.
export { InMemoryLedger as NoteLedger };
