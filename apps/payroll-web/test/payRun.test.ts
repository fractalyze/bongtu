// Gate for the pay run's OUTER contract (lib/payRun.ts) — the two things that
// decide what the operator is told when a run does not finish:
//
//   (1) the batch bounds, checked before any leg runs, so an impossible sheet
//       fails in the instant after the click rather than after minutes of merges;
//   (2) the terminal-leg failure wording — once merge transactions have LANDED,
//       a bare "failed" reads like lost payroll, so the money state is named.
//
// The run's I/O edges are injected (PayRunDeps), so the whole terminal leg runs
// here with no wallet, no indexer and no prover.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import {
  MAX_RECIPIENTS,
  PAY_RUN_FAILURE_REASSURANCE,
  runPayRun,
  type PayRunContext,
  type PayRunDeps,
} from "../src/lib/payRun.js";
import type { RecipientRow } from "../src/lib/disburse.js";

const KKRW = 10n ** 18n;
const PAYEE = packPubkey(deriveKeypair(7000000019n).publicKey);
const IDENTITY = { compressedPubkey: PAYEE, keypair: { formattedPrivateKey: 42n } };

const recipients = (n: number): RecipientRow[] =>
  Array.from({ length: n }, (_, i) => ({
    pubkey: packPubkey(deriveKeypair(7100000000n + BigInt(i) * 1009n).publicKey),
    amount: KKRW.toString(),
  }));

const CTX = {
  connection: {},
  indexerUrl: "http://indexer.test",
  pool: "0xpool",
  explorer: "http://explorer.test",
  notes: [],
  sessionPubkey: PAYEE,
  reloadNotes: async () => [],
} as unknown as PayRunContext;

const OUTCOME = { txHash: "0xmerge", explorerUrl: "http://explorer.test/0xmerge" };

/** Deps whose every edge is a double. `merges` is how many merge transactions the
 *  chain reports as LANDED before the terminal leg; `getHead` is where this suite
 *  makes the terminal leg fail (the first indexer read it performs). */
function deps(opts: { merges: number; headError?: Error }): PayRunDeps & { mergeCalls: number } {
  const d = {
    mergeCalls: 0,
    prove: (async () => {
      throw new Error("the terminal leg must fail before proving in this suite");
    }) as PayRunDeps["prove"],
    keyCache: {
      isUnlocked: () => true,
      unlock: async () => IDENTITY,
    } as unknown as PayRunDeps["keyCache"],
    runMergeChain: (async () => {
      d.mergeCalls++;
      return {
        funding: { value: (1000n * KKRW).toString(), salt: "7", leafIndex: 0 },
        mergeTxs: Array.from({ length: opts.merges }, () => OUTCOME),
      };
    }) as unknown as PayRunDeps["runMergeChain"],
    ensureChain: (async () => {}) as PayRunDeps["ensureChain"],
    assertPoolKemEpoch: (async () => {}) as PayRunDeps["assertPoolKemEpoch"],
    getHead: (async () => {
      throw opts.headError ?? new Error("indexer is down");
    }) as unknown as PayRunDeps["getHead"],
  };
  return d;
}

const noop = (): void => {};

// ---------------------------- (1) the batch bounds --------------------------------

test("an empty sheet and an over-B-1 sheet are refused before ANY leg runs", async () => {
  for (const rows of [recipients(0), recipients(MAX_RECIPIENTS + 1)]) {
    const d = deps({ merges: 0 });
    await assert.rejects(runPayRun(CTX, rows, noop, d));
    assert.equal(d.mergeCalls, 0, "nothing is signed for a sheet that cannot be paid");
  }
});

test("the bound is B-1 — the last output slot is the employer's change note", async () => {
  assert.equal(MAX_RECIPIENTS, 255);
  const d = deps({ merges: 0 });
  await assert.rejects(
    runPayRun(CTX, recipients(MAX_RECIPIENTS + 1), noop, d),
    (e: Error) => e.message.includes("255") && e.message.includes("256"),
    "the cap and what the sheet actually holds",
  );
  // …and exactly B-1 is allowed through to the run itself.
  await assert.rejects(runPayRun(CTX, recipients(MAX_RECIPIENTS), noop, d), /indexer is down/);
  assert.equal(d.mergeCalls, 1);
});

// ---------------------------- (2) terminal-leg wording ----------------------------

test("a terminal failure AFTER landed merges says the money is safe and the retry is shorter", async () => {
  await assert.rejects(
    runPayRun(CTX, recipients(3), noop, deps({ merges: 2 })),
    (e: Error) =>
      e.message.includes(PAY_RUN_FAILURE_REASSURANCE) &&
      e.message.includes("indexer is down") &&
      /nobody was paid/.test(e.message),
    "two signed transactions landed and nobody was paid — that must be said",
  );
});

test("the wrapped headline is the console's wording, not the raw thrown value", async () => {
  // A declined wallet popup on the terminal leg goes through payrollErrorMessage,
  // so the operator reads the verdict, not the provider's error string.
  const rejected = Object.assign(new Error("User rejected the request"), { code: 4001 });
  await assert.rejects(
    runPayRun(CTX, recipients(3), noop, deps({ merges: 1, headError: rejected })),
    (e: Error) =>
      e.message.startsWith("Transaction rejected in your wallet.") &&
      e.message.includes(PAY_RUN_FAILURE_REASSURANCE),
  );
});

test("a run with NO merges throws the plain error — there is no chain to reassure about", async () => {
  await assert.rejects(
    runPayRun(CTX, recipients(3), noop, deps({ merges: 0 })),
    (e: Error) => e.message === "indexer is down" && !e.message.includes(PAY_RUN_FAILURE_REASSURANCE),
    "one signature, one failure: the chain wording would only puzzle",
  );
});
