// Headless gate for `deriveHistory` (src/ledger.ts) — the pure envelope → per-owner
// activity step behind GET /history. The conformance ladder (test/ingest.test.ts)
// exercises it through real decrypted envelopes; this table drives it DIRECTLY with
// hand-built ParsedEnvelope values, so each rule in the comment above deriveHistory
// has a case that fails in milliseconds when the rule moves:
//
//   - a split payment yields one "received" AND one "sent" PER non-self output,
//     never a single merged item;
//   - a transfer's self output is CHANGE and is not listed…
//   - …unless every nonzero output is a self output (a pure self-send), which
//     yields a "sent" + "received" pair over the payment slot;
//   - the payment slot is the first NONZERO output, so a consolidation merge that
//     puts 0 in output 0 still reports the merged sum;
//   - only a cross-checked disburse batch contributes anything;
//   - a withdraw with nothing unshielded (change == inputs) reports nothing;
//   - zero-value notes (pads, residues, zero change) never produce an item.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";
import type { EnvNote, OpKind, ParsedEnvelope } from "@bongtu/core/envelope";
import { deriveHistory, type DerivedHistory } from "../src/ledger.js";
import type { OpEnvelope } from "../src/ledger.js";

const A = deriveKeypair(111111111111111111n).publicKey; // the sender / employer
const B = deriveKeypair(222222222222222222n).publicKey; // payee #1
const C = deriveKeypair(333333333333333333n).publicKey; // payee #2

/** deriveHistory reads only `op.kind`; everything else is carried for the record. */
const op = (kind: OpKind): OpEnvelope => ({
  kind,
  txHash: `0x${kind}`,
  logIndex: 0,
  blockTimestamp: 1_700_000_000,
  ecdhPublicKey: [1n, 2n],
  nonce: 3n,
  authorityCt: [],
  kem: null,
  outputLeaves: [],
});

const note = (owner: Point, value: bigint): EnvNote => ({ owner, value, salt: 42n });
const env = (inputs: EnvNote[], outputs: EnvNote[]): ParsedEnvelope => ({ inputs, outputs });

const LABEL = new Map<string, string>([
  [`${A[0]},${A[1]}`, "A"],
  [`${B[0]},${B[1]}`, "B"],
  [`${C[0]},${C[1]}`, "C"],
]);
const who = (p: Point | null): string | null => (p === null ? null : LABEL.get(`${p[0]},${p[1]}`) ?? "?");

/** The readable shape of a draft: who it belongs to, what it says, how much. */
const shape = (h: DerivedHistory): [string | null, string, string | null, string] => [
  who(h.owner),
  h.kind,
  who(h.counterparty),
  h.amount.toString(),
];

test("transfer to two distinct payees: one received AND one sent per output", () => {
  const drafts = deriveHistory(op("transfer"), env([note(A, 20n), note(A, 0n)], [note(B, 5n), note(C, 15n)]), false);
  assert.deepEqual(drafts.map(shape), [
    ["B", "received", "A", "5"],
    ["A", "sent", "B", "5"],
    ["C", "received", "A", "15"],
    ["A", "sent", "C", "15"],
  ]);
});

test("transfer with self change: the change output is not listed", () => {
  const drafts = deriveHistory(op("transfer"), env([note(A, 30n), note(A, 0n)], [note(B, 12n), note(A, 18n)]), false);
  assert.deepEqual(drafts.map(shape), [
    ["B", "received", "A", "12"],
    ["A", "sent", "B", "12"],
  ]);
});

test("pure self-send: a sent + received pair over the payment slot, sent emitted first", () => {
  const drafts = deriveHistory(op("transfer"), env([note(A, 30n), note(A, 0n)], [note(A, 12n), note(A, 18n)]), false);
  // Emission order is load-bearing: the recording adapter assigns seq in this
  // order and the feed sorts seq DESC, so "sent" first == received-above-sent.
  assert.deepEqual(drafts.map(shape), [
    ["A", "sent", "A", "12"],
    ["A", "received", "A", "12"],
  ]);
});

test("consolidation merge with a zero payment slot: the pair carries the merged sum", () => {
  const drafts = deriveHistory(op("transfer"), env([note(A, 12n), note(A, 18n)], [note(A, 0n), note(A, 30n)]), false);
  assert.deepEqual(drafts.map(shape), [
    ["A", "sent", "A", "30"],
    ["A", "received", "A", "30"],
  ]);
});

test("transfer10x2 payee + change over 4 real inputs derives exactly a transfer's rows", () => {
  // The 10-input arity must not leak into the feed: only the outputs drive the
  // rows, so 4 real inputs + 6 zero pads with a payee + self change reads
  // byte-identically to the arity-2 "self change" case above.
  const ins = [note(A, 10n), note(A, 20n), note(A, 30n), note(A, 40n), ...Array.from({ length: 6 }, () => note(A, 0n))];
  const drafts = deriveHistory(op("transfer10x2"), env(ins, [note(B, 70n), note(A, 30n)]), false);
  assert.deepEqual(drafts.map(shape), [
    ["B", "received", "A", "70"],
    ["A", "sent", "B", "70"],
  ]);
});

test("transfer10x2 merge with both outputs self surfaces as the self-send pair", () => {
  // A consolidation merge would otherwise vanish under change suppression
  // (fractalyze/bongtu#1) — the pair carries the payment slot (the merged sum).
  const ins = [note(A, 60n), note(A, 40n), ...Array.from({ length: 8 }, () => note(A, 0n))];
  const drafts = deriveHistory(op("transfer10x2"), env(ins, [note(A, 100n), note(A, 0n)]), false);
  assert.deepEqual(drafts.map(shape), [
    ["A", "sent", "A", "100"],
    ["A", "received", "A", "100"],
  ]);
});

test("transfer whose outputs are all zero yields nothing at all", () => {
  const drafts = deriveHistory(op("transfer"), env([note(A, 0n), note(A, 0n)], [note(A, 0n), note(B, 0n)]), false);
  assert.deepEqual(drafts, []);
});

test("disburse: an uncross-checked batch contributes NOTHING", () => {
  const batch = env([note(A, 9n), note(A, 0n)], [note(B, 3n), note(C, 6n)]);
  assert.deepEqual(deriveHistory(op("disburse"), batch, false), []);
  // Control: the same batch, cross-checked, is a "received" per non-self output.
  assert.deepEqual(deriveHistory(op("disburse"), batch, true).map(shape), [
    ["B", "received", "A", "3"],
    ["C", "received", "A", "6"],
  ]);
});

test("withdraw: net unshielded only, and nothing when the change equals the inputs", () => {
  const partial = env([note(A, 30n), note(A, 0n)], [note(A, 18n)]);
  assert.deepEqual(deriveHistory(op("withdraw"), partial, false).map(shape), [["A", "withdraw", null, "12"]]);
  const nothingLeft = env([note(A, 30n), note(A, 0n)], [note(A, 30n)]);
  assert.deepEqual(deriveHistory(op("withdraw"), nothingLeft, false), []);
});

test("deposit: each of the depositor's own nonzero outputs, pads excluded", () => {
  const drafts = deriveHistory(op("deposit"), env([], [note(A, 25n), note(A, 0n)]), false);
  assert.deepEqual(drafts.map(shape), [["A", "deposit", null, "25"]]);
});
