// Arbiter-mode note ledger (SPEC §6b v2 enforced auditor disclosure).
//
// Built ONLY when the indexer holds the arbiter PRIVATE key (AUTHORITY_KEY set).
// For every op, in chain order, it decrypts the op's authority envelope
// (@bongtu/sdk/envelope — the owning codec) and:
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
//     counterparty + amount that op meant for each owner. No re-decrypt — it is
//     read off `env` alongside the note directory (recordHistory below).
//
// The arbiter private key lives in this object and is NEVER serialized into any
// HTTP response or log line — only recovered note fields (which are exactly what
// the auditor is entitled to see) ever leave here.

import { commitment as noteCommitment } from "@bongtu/sdk/note";
import { ImtTree } from "@bongtu/sdk/imt";
import { packPubkey } from "@bongtu/sdk/pubkey";
import type { Point } from "@bongtu/sdk/babyjub";
import type { MirrorTree } from "./tree.js";
import { parseEnvelope, type EnvNote, type OpKind, type ParsedEnvelope } from "@bongtu/sdk/envelope";

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
 * owned by @bongtu/sdk/indexerApi (HistoryItem) — this stays structurally equal.
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

export class NoteLedger {
  private readonly arbiterPriv: bigint; // NEVER leaves this object
  private readonly B: number;
  private readonly tree: MirrorTree;
  private readonly byOwner = new Map<string, LedgerNote[]>();
  private readonly byCommitment = new Map<string, LedgerNote>();
  private readonly alarms: EnvelopeAlarm[] = [];
  // Per-owner activity history (GET /history), keyed by owner pubkey. Appended in
  // chain-apply order; `historySeq` is the monotonic ordering key. Built from the
  // SAME decrypted envelopes as the note directory — no separate decrypt.
  private readonly historyByOwner = new Map<string, LedgerHistoryItem[]>();
  private historySeq = 0;
  // (txHash, logIndex) of every op already applied — the ledger guards its OWN
  // replay invariant (the same self-guarding pattern as MirrorTree / Store), so
  // a replayed log range cannot double-record notes or re-flip spent flags even
  // if a future ingest reordering drops the Store-side gating.
  private readonly applied = new Set<string>();

  constructor(arbiterPriv: bigint, B: number, tree: MirrorTree) {
    this.arbiterPriv = arbiterPriv;
    this.B = B;
    this.tree = tree;
  }

  private ownerKey(x: bigint, y: bigint): string {
    return `${x},${y}`;
  }

  /**
   * Ingest one op's envelope in chain order: verify + record outputs, mark inputs
   * spent, and (disburse) fill the batch leaves so /path can serve into it.
   * Replay-safe: idempotent on (txHash, logIndex), so it may be called
   * unconditionally per log — ingest's Store-side gating is belt-and-braces,
   * not what the ledger's correctness hangs on.
   */
  apply(op: OpEnvelope): void {
    const key = `${op.txHash}:${op.logIndex}`;
    if (this.applied.has(key)) return; // replayed op — already recorded
    this.applied.add(key);
    const env = parseEnvelope(this.arbiterPriv, op.ecdhPublicKey, op.nonce, op.authorityCt, op.kind, this.B);

    // A disburse contributes "received" history only when its batch cross-checks
    // (fold == on-chain subtreeRoot); a tampered batch is an alarm, not activity.
    let disburseVerified = false;
    if (op.kind === "disburse") {
      // Cross-check: fold the B recovered commitments to a subtree root and
      // compare to the on-chain subtreeRoot. On match, record the notes and fill
      // the batch (arbiter /path becomes servable); a mismatch is an ALARM and
      // the batch stays unopened (path() keeps returning the 422 sentinel).
      const start = op.batch!.startLeafIndex;
      const commits = env.outputs.map((o) => noteCommitment(o.value, o.salt, o.owner));
      const sub = new ImtTree(this.tree.H, this.B).computeSubtreeRoot(commits);
      if (sub !== op.batch!.subtreeRoot) {
        this.alarm(op.kind, op.txHash, `disburse batch @${start}: envelope leaves fold != on-chain subtreeRoot`, sub, op.batch!.subtreeRoot);
      } else {
        for (let i = 0; i < this.B; i++) this.addOutput(env.outputs[i], start + i, commits[i], op.txHash);
        this.tree.fillBatch(start, commits);
        disburseVerified = true;
      }
    } else {
      // deposit / transfer / withdraw: each recovered output must reproduce a
      // known on-chain leaf commitment, in order.
      for (let i = 0; i < op.outputLeaves.length; i++) {
        const o = env.outputs[i];
        const c = noteCommitment(o.value, o.salt, o.owner);
        const known = op.outputLeaves[i];
        if (c !== known.commitment) {
          this.alarm(op.kind, op.txHash, `output#${i} @${known.leafIndex}: envelope commitment != on-chain leaf`, c, known.commitment);
          continue; // do not record an unverifiable note
        }
        this.addOutput(o, known.leafIndex, c, op.txHash);
      }
    }

    // INPUT notes mark the matching created note spent (envelope-based, keyed by
    // commitment). A padded/disabled input (value 0, throw-away salt) simply has
    // no matching created note, so it is a harmless no-op.
    for (const inp of env.inputs) {
      const note = this.byCommitment.get(dec(noteCommitment(inp.value, inp.salt, inp.owner)));
      if (note) note.spent = true;
    }

    this.recordHistory(op, env, disburseVerified);
  }

  /**
   * Derive per-owner activity items from the op's decrypted envelope (no
   * re-decrypt — `env` is what the note directory was built from). Zero-value
   * notes (pads, residues, zero change) contribute nothing. Semantics per SPEC
   * §6b / LedgerHistoryItem:
   *   - deposit:  each of the depositor's own outputs → "deposit".
   *   - transfer: the input owner is the sender; each non-self output → a
   *     "received" for its owner (counterparty = sender) AND a matching "sent"
   *     for the sender (counterparty = that payee, amount = that output). Both
   *     outputs can be independent payees (2-out, free owners), so a split
   *     payment yields two "sent" items, never one merged item. A self output is
   *     the sender's change and is NOT listed.
   *   - disburse: each non-self output → "received" (counterparty = the employer
   *     input owner). Only a cross-checked batch contributes.
   *   - withdraw: the input owner unshielded inputs − change → "withdraw".
   */
  private recordHistory(op: OpEnvelope, env: ParsedEnvelope, disburseVerified: boolean): void {
    switch (op.kind) {
      case "deposit":
        for (const o of env.outputs) {
          if (o.value !== 0n) this.pushHistory(o.owner, "deposit", null, o.value, op);
        }
        return;
      case "disburse": {
        if (!disburseVerified) return;
        const sender = env.inputs[0].owner;
        for (const o of env.outputs) {
          if (o.value !== 0n && !this.sameOwner(o.owner, sender)) {
            this.pushHistory(o.owner, "received", sender, o.value, op);
          }
        }
        return;
      }
      case "transfer": {
        // transfer is 2-out with INDEPENDENT output owners (only the inputs share
        // one key), so both outputs can be distinct non-self payees. Emit one
        // "received" AND one matching "sent" per non-self output — never collapse
        // a split payment into a single item to outputs[0].owner.
        const sender = env.inputs[0].owner;
        for (const o of env.outputs) {
          if (o.value !== 0n && !this.sameOwner(o.owner, sender)) {
            this.pushHistory(o.owner, "received", sender, o.value, op);
            this.pushHistory(sender, "sent", o.owner, o.value, op);
          }
        }
        return;
      }
      case "withdraw": {
        const owner = env.inputs[0].owner;
        const inSum = env.inputs.reduce((a, i) => a + i.value, 0n);
        const change = env.outputs.reduce((a, o) => a + o.value, 0n);
        const withdrawn = inSum - change;
        if (withdrawn > 0n) this.pushHistory(owner, "withdraw", null, withdrawn, op);
        return;
      }
    }
  }

  private sameOwner(a: Point, b: Point): boolean {
    return a[0] === b[0] && a[1] === b[1];
  }

  private pushHistory(owner: Point, kind: HistoryKind, counterparty: Point | null, amount: bigint, op: OpEnvelope): void {
    const item: LedgerHistoryItem = {
      kind,
      counterparty: counterparty ? packPubkey(counterparty) : null,
      amount: dec(amount),
      txHash: op.txHash,
      blockTimestamp: op.blockTimestamp,
      seq: this.historySeq++,
    };
    const k = this.ownerKey(owner[0], owner[1]);
    const arr = this.historyByOwner.get(k) ?? [];
    arr.push(item);
    this.historyByOwner.set(k, arr);
  }

  private addOutput(o: EnvNote, leafIndex: number, c: bigint, txHash: string): void {
    const note: LedgerNote = {
      owner: [dec(o.owner[0]), dec(o.owner[1])],
      value: dec(o.value),
      salt: dec(o.salt),
      leafIndex,
      commitment: dec(c),
      txHash,
      spent: false,
    };
    const k = this.ownerKey(o.owner[0], o.owner[1]);
    const arr = this.byOwner.get(k) ?? [];
    arr.push(note);
    this.byOwner.set(k, arr);
    this.byCommitment.set(note.commitment, note);
  }

  private alarm(kind: OpKind, txHash: string, detail: string, recomputed: bigint, expected: bigint): void {
    const a: EnvelopeAlarm = { kind, txHash, detail, recomputed: dec(recomputed), expected: dec(expected) };
    this.alarms.push(a);
    console.error(`ALARM envelope ${kind} tx=${txHash} ${detail} recomputed=${a.recomputed} expected=${a.expected}`);
  }

  /** Every note owned by (x,y) — the arbiter's authoritative view of that owner. */
  notesOf(ownerX: bigint, ownerY: bigint): LedgerNote[] {
    return this.byOwner.get(this.ownerKey(ownerX, ownerY)) ?? [];
  }

  /** One owner's activity history (GET /history), newest-first (seq desc). */
  historyOf(ownerX: bigint, ownerY: bigint): LedgerHistoryItem[] {
    const arr = this.historyByOwner.get(this.ownerKey(ownerX, ownerY)) ?? [];
    return [...arr].sort((a, b) => b.seq - a.seq);
  }

  /** Envelope cross-check failures surfaced during ingest (auditor-console feed). */
  getEnvelopeAlarms(): EnvelopeAlarm[] {
    return this.alarms;
  }
}
