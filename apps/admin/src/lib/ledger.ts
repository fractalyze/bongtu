// PURE auditor-mode ledger builder (SPEC §7 auditor-mode, §6b enforced disclosure).
//
// The auditor holds the arbiter PRIVATE key. Given the PUBLIC /events feed (raw
// ciphertext + ecdhPublicKey + nonce per op), it decrypts each op's AUTHORITY
// envelope with the arbiter key and reconstructs "who received what / spent status"
// — the independent regulator view, needing no user private key.
//
// Reuses the indexer's own envelope decrypt/parse (indexer/src/envelope.ts) so the
// auditor app and the indexer agree byte-for-byte. It does NOT modify the indexer.
//
// Coverage boundary (honest): the public /events feed carries an authority tail
// only for `transfer` and `disburse` (deposit/withdraw emit their authority
// envelope in the raw Deposited/Withdrawn log, which the public feed strips —
// ingest.ts sets their `ciphertext: []`). So this local decrypt reconstructs the
// transfer + disburse ledger (exactly the compliance demo beat: the auditor reads
// employees' p2p transfers AND the 256-recipient batch). Deposit/withdraw notes are
// surfaced as "no authority envelope in the public feed" — for those an arbiter-mode
// indexer's own /notes directory is the source.

import { parseEnvelope, envelopePlaintextLen, type OpKind } from "../../../../indexer/src/envelope.js";
import { commitment as noteCommitment } from "../../../../sdk/src/note.js";
import { packPubkey } from "../../../../sdk/src/pubkey.js";

/** One /events entry (the subset the ledger needs), as returned by GET /events. */
export interface FeedEvent {
  seq: number;
  txHash: string;
  blockNumber: number;
  kind: OpKind;
  epoch: number | null;
  ecdhPublicKey: [string, string] | null;
  encryptionNonce: string | null;
  slices: { offset: number; elts: number; leafIndex: number | null }[];
  ciphertext: string[];
  disclosure?: string;
}

/** A decrypted note in the auditor ledger. */
export interface LedgerNote {
  owner: string; // compressed bjj pubkey (the on-wire identifier)
  value: string;
  salt: string;
  leafIndex: number | null;
  commitment: string;
  txHash: string;
  kind: OpKind;
  spent: boolean;
}

/** Per-op summary for the auditor feed table. */
export interface OpSummary {
  seq: number;
  txHash: string;
  blockNumber: number;
  kind: OpKind;
  epoch: number | null;
  disclosure?: string;
  decoded: boolean;
  reason?: string;
  realOutputs?: number;
  totalOutputs?: number;
  spentInputs?: number;
}

export interface AuditorLedger {
  /** every decrypted note, keyed by compressed owner pubkey. */
  byOwner: Map<string, LedgerNote[]>;
  /** flat chronological note list. */
  notes: LedgerNote[];
  /** per-op summaries (decoded or skipped-with-reason), chain order. */
  ops: OpSummary[];
}

// Poseidon-sponge ciphertext length for an op's authority plaintext: pad the
// plaintext to a multiple of 3, then +1 (the sponge's final squeeze). The authority
// envelope is always the TAIL of the on-chain ciphertext.
function authorityCtLen(kind: OpKind, B: number): number {
  const plain = envelopePlaintextLen(kind, B);
  const pad = (3 - (plain % 3)) % 3;
  return plain + pad + 1;
}

/**
 * Decrypt the transfer/disburse authority envelopes in `events` with the arbiter
 * private key and build the ledger. `arbiterPriv` is a decimal bjj scalar. Never
 * throws on a single bad op — an undecryptable/short op is recorded as
 * `decoded:false` with a reason so the console can show it.
 */
export function buildAuditorLedger(events: FeedEvent[], arbiterPriv: string, B: number): AuditorLedger {
  const priv = BigInt(arbiterPriv);
  const byOwner = new Map<string, LedgerNote[]>();
  const byCommitment = new Map<string, LedgerNote>();
  const notes: LedgerNote[] = [];
  const ops: OpSummary[] = [];

  const record = (n: LedgerNote): void => {
    notes.push(n);
    const arr = byOwner.get(n.owner) ?? [];
    arr.push(n);
    byOwner.set(n.owner, arr);
    byCommitment.set(n.commitment, n);
  };

  for (const e of [...events].sort((a, b) => a.seq - b.seq)) {
    const base: OpSummary = {
      seq: e.seq,
      txHash: e.txHash,
      blockNumber: e.blockNumber,
      kind: e.kind,
      epoch: e.epoch,
      disclosure: e.disclosure,
      decoded: false,
    };
    if (!e.ecdhPublicKey || e.encryptionNonce == null || e.ciphertext.length === 0) {
      ops.push({ ...base, reason: "no authority envelope in the public /events feed (deposit/withdraw strip it, §6b)" });
      continue;
    }
    const ct = e.ciphertext.map((x) => BigInt(x));
    const need = authorityCtLen(e.kind, B);
    if (ct.length < need) {
      ops.push({ ...base, reason: `ciphertext (${ct.length}) shorter than the ${e.kind} authority envelope (${need})` });
      continue;
    }
    const authorityCt = ct.slice(ct.length - need); // authority tail
    const ecdh: [bigint, bigint] = [BigInt(e.ecdhPublicKey[0]), BigInt(e.ecdhPublicKey[1])];
    const nonce = BigInt(e.encryptionNonce);
    let parsed;
    try {
      parsed = parseEnvelope(priv, ecdh, nonce, authorityCt, e.kind, B);
    } catch (err) {
      ops.push({ ...base, reason: `authority decrypt failed: ${(err as Error).message}` });
      continue;
    }

    // Output leaf indices, in output order, from the non-authority slices.
    const outLeaves = e.slices.filter((s) => s.leafIndex != null).map((s) => s.leafIndex as number);
    parsed.outputs.forEach((o, i) => {
      const c = noteCommitment(o.value, o.salt, o.owner);
      record({
        owner: packPubkey(o.owner),
        value: o.value.toString(),
        salt: o.salt.toString(),
        leafIndex: i < outLeaves.length ? outLeaves[i] : null,
        commitment: c.toString(),
        txHash: e.txHash,
        kind: e.kind,
        spent: false,
      });
    });

    // Inputs mark the matching earlier output spent (envelope-based, by commitment).
    let spentInputs = 0;
    for (const inp of parsed.inputs) {
      const c = noteCommitment(inp.value, inp.salt, inp.owner).toString();
      const n = byCommitment.get(c);
      if (n) {
        n.spent = true;
        spentInputs++;
      }
    }

    ops.push({
      ...base,
      decoded: true,
      realOutputs: parsed.outputs.filter((o) => o.value > 0n).length,
      totalOutputs: parsed.outputs.length,
      spentInputs,
    });
  }

  return { byOwner, notes, ops };
}
