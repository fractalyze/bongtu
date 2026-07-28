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
//     (GET /history): activity items (kinds: LedgerHistoryItem below) with the
//     counterparty + amount that op meant for each owner.
//
// This module holds the PURE half of the ledger: the decrypt/derive step —
// envelope → (output notes, spent-marks, cross-check alarms, batch fill,
// history) — is ONE shared PURE function `deriveOp`, holding ALL of the crypto
// (parseEnvelope, commitment fold, subtree cross-check, history derivation),
// plus the small record/map helpers. The RECORD/READ half lives in
// `PostgresLedger` (src/postgres.ts) — the ONLY runtime ledger (U-I4
// Postgres-only): it keeps byOwner/byCommitment/historyByOwner/applied maps as
// a boot-hydrated read model AND persists each derived op to SQL.
//
// The arbiter private key lives in the ledger object and is NEVER serialized into
// any HTTP response or log line — only recovered note fields (which are exactly
// what the auditor is entitled to see) ever leave here.

import { commitment as noteCommitment } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { packPubkey } from "@bongtu/core/pubkey";
import { ml_kem768, kemSsToLimbs, kemBindingOf } from "@bongtu/core/kem";
import type { Point } from "@bongtu/core/babyjub";
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
 *     the payee, amount = what left them). A pure self-send is a "sent" +
 *     "received" pair, both owned by and addressed to the sender;
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
  // The op's hybrid-envelope KEM material off the V2 event (kemBinding public
  // signal + the raw 1088-byte ML-KEM-768 ct). null == a pre-KEM (V1-ABI) op:
  // legacy raw-ECDH decrypt, KEM checks skipped — the structural pre-upgrade
  // gate of pq-envelope-design.md §5 (no epoch arithmetic, no false alarms).
  kem: { binding: bigint; ciphertext: Uint8Array } | null;
  outputLeaves: { leafIndex: number; commitment: bigint }[];
  batch?: { startLeafIndex: number; subtreeRoot: bigint }; // disburse only
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
 *
 * `kemSecret` is the arbiter's ML-KEM-768 decapsulation key (AUTHORITY_KEM_KEY).
 * A V2 op (op.kem set) is decapsulated FIRST and its recomputed
 * Poseidon(3)(TAG_BIND, limbs) compared to the on-chain kemBinding: a mismatch
 * is a junk-wrapped ct (design doc §2 trade-off) — first-class EnvelopeAlarm,
 * op STOPPED (no notes, no batch fill, no history, envelope withheld). On
 * match, the decapsulated limbs feed the hybrid envelope key; a V1 op
 * (op.kem null) keeps the legacy raw-ECDH key.
 */
export function deriveOp(
  arbiterPriv: bigint,
  kemSecret: Uint8Array | null,
  B: number,
  treeH: number,
  op: OpEnvelope,
): DerivedOp {
  let kemSs: [bigint, bigint] | undefined;
  if (op.kem) {
    if (!kemSecret) {
      // The kem boot guard (§7) refuses to serve in exactly this configuration;
      // throwing (not alarming) keeps a misconfigured arbiter from recording a
      // false "tamper" verdict against an honest op.
      throw new Error("deriveOp: op carries KEM material but no AUTHORITY_KEM_KEY is configured");
    }
    // Decapsulation can only throw on wire-size violations (the contract's
    // WrongKemCiphertextLength makes that unreachable from real logs today);
    // if the invariant ever slips upstream, alarm-and-withhold like any other
    // bad envelope — a throw here would crashloop ingest on the persisted
    // cursor re-hitting the same op forever.
    let decapsulated: Uint8Array;
    try {
      decapsulated = ml_kem768.decapsulate(op.kem.ciphertext, kemSecret);
    } catch (e) {
      return {
        outputs: [],
        spent: [],
        alarms: [{
          kind: op.kind,
          txHash: op.txHash,
          detail: `kem decapsulation failed (${e instanceof Error ? e.message : String(e)}) — envelope withheld`,
          recomputed: "0",
          expected: dec(op.kem.binding),
        }],
        batchFill: null,
        history: [],
      };
    }
    const limbs = kemSsToLimbs(decapsulated);
    const recomputed = kemBindingOf(limbs);
    if (recomputed !== op.kem.binding) {
      return {
        outputs: [],
        spent: [],
        alarms: [{
          kind: op.kind,
          txHash: op.txHash,
          detail: "kem binding mismatch — envelope withheld",
          recomputed: dec(recomputed),
          expected: dec(op.kem.binding),
        }],
        batchFill: null,
        history: [],
      };
    }
    kemSs = limbs;
  }
  const env = parseEnvelope(arbiterPriv, op.ecdhPublicKey, op.nonce, op.authorityCt, op.kind, B, kemSs);
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
 *   - transfer / transfer10 / transfer10x2 (same rule, N = 2 or 10): the input
 *     owner is the sender; each non-self output → a "received"
 *     for its owner (counterparty = sender) AND a matching "sent" for the sender
 *     (counterparty = that payee). Both outputs can be independent payees, so a
 *     split payment yields two "sent" items, never one merged item. A self output
 *     is the sender's change and is NOT listed. That change-suppression rule
 *     predates self-send (SPEC §6b was written when the circuit still rejected
 *     duplicate output owners), so a PURE self-send — every nonzero output back
 *     to the sender, legal since the §11-8 v1.1 per-output nonce — would erase
 *     the op from the feed entirely (fractalyze/bongtu#1). That case emits a
 *     "sent" AND a "received", both owned by the sender with the sender as
 *     counterparty, amount = the payment slot (output 0 — a consolidation merge
 *     carries the whole merged sum there). A matched pair nets to zero and reads
 *     like every other row, where the older single "self" item needed its own
 *     verb and its own neutral amount styling in every client.
 *   - disburse: each non-self output → "received" (counterparty = the employer
 *     input owner). Only a cross-checked batch contributes.
 *   - withdraw: the input owner unshielded inputs − change → "withdraw".
 */
export function deriveHistory(op: OpEnvelope, env: ParsedEnvelope, disburseCrossChecks: boolean): DerivedHistory[] {
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
    case "transfer":
    case "transfer10":
    case "transfer10x2": {
      // transfer is N-out with INDEPENDENT output owners, so every output can be
      // a distinct non-self payee: emit one "received" AND one matching "sent" per
      // non-self output — never collapse a split payment into a single item. The
      // 10-input circuits differ only in N (10 outputs, or 2), so they derive
      // identically.
      const sender = env.inputs[0].owner;
      // A pure self-send has NO non-self output, so the change suppression below
      // would erase the op from the owner's feed entirely (fractalyze/bongtu#1):
      // emit the "sent"/"received" pair instead, amount = the payment slot.
      const nonzero = env.outputs.filter((o) => o.value !== 0n);
      if (nonzero.length > 0 && nonzero.every((o) => sameOwner(o.owner, sender))) {
        // nonzero[0], not outputs[0]: a hand-built tx can put 0 in the payment
        // slot; the wallet's shapes (payment at 0, merge sum at 0) are unchanged.
        // "sent" is pushed first, so in the seq-DESC feed the pair reads
        // received-above-sent, matching the newest-last emission order.
        out.push({ owner: sender, kind: "sent", counterparty: sender, amount: nonzero[0].value });
        out.push({ owner: sender, kind: "received", counterparty: sender, amount: nonzero[0].value });
        return out;
      }
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
// RECORD helpers — the small map/console ops PostgresLedger's read model uses
// (no crypto). Free functions so the recording side stays plain bookkeeping.
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

/**
 * Append a history item to its owner's list, keeping that list sorted by ASCENDING
 * seq.
 *
 * That ordering is an INVARIANT the paged read relies on (PostgresLedger.historyOf
 * binary-searches `before` and walks backwards for the newest-first page, instead
 * of copy-sorting the whole feed per request). Both producers already push in
 * order — apply() stamps a monotonically increasing `historySeq`, and boot()
 * replays `ORDER BY seq ASC` — so the fast path is a plain append. The ordered
 * insert is a belt for a future producer that is not: it keeps the invariant true
 * by construction rather than by comment, and costs nothing until it is needed.
 */
export function pushHistory(historyByOwner: Map<string, LedgerHistoryItem[]>, owner: Point, item: LedgerHistoryItem): void {
  const k = ownerKey(owner[0], owner[1]);
  const arr = historyByOwner.get(k) ?? [];
  if (arr.length > 0 && item.seq <= arr[arr.length - 1].seq) {
    let i = arr.length;
    while (i > 0 && arr[i - 1].seq > item.seq) i--;
    arr.splice(i, 0, item);
  } else {
    arr.push(item);
  }
  historyByOwner.set(k, arr);
}

/** The auditor-console line for an envelope cross-check failure. */
export function logEnvelopeAlarm(a: EnvelopeAlarm): void {
  console.error(`ALARM envelope ${a.kind} tx=${a.txHash} ${a.detail} recomputed=${a.recomputed} expected=${a.expected}`);
}

