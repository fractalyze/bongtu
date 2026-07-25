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
// The arbiter private key lives in this object and is NEVER serialized into any
// HTTP response or log line — only recovered note fields (which are exactly what
// the auditor is entitled to see) ever leave here.

import { commitment as noteCommitment } from "@bongtu/sdk/note";
import { ImtTree } from "@bongtu/sdk/imt";
import type { MirrorTree } from "./tree.js";
import { parseEnvelope, type EnvNote, type OpKind } from "@bongtu/sdk/envelope";

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

  /** Envelope cross-check failures surfaced during ingest (auditor-console feed). */
  getEnvelopeAlarms(): EnvelopeAlarm[] {
    return this.alarms;
  }
}
