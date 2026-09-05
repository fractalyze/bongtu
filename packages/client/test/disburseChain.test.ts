// Headless gate for the payroll DISBURSE CHAIN (U-P3): the terminal disburse
// circuit spends exactly ONE input note, so a balance spread across several must
// first be folded down by transfer10x2 self-merges. The package owns that fold —
// planDisburseChain (pure) + runMergeChain (the flow) — and hands the caller the
// single funding note; the terminal 1-in/256-out transaction itself is the app's
// (payroll-web lib/disburse.ts + submitDisburse), deliberately NOT here.
//
//   (1) PLAN — the whole decision table as a table test: zero merges when one note
//       covers, folds of the LARGEST notes when not, stop-the-moment-it-covers,
//       and the `insufficient` refusal before any leg is planned.
//   (2) RUN — runMergeChain against a fake chain+indexer (the spendChain.test.ts
//       world, compacted): merge legs land as transfer10x2 self-sends, the chain
//       waits for the indexer between legs, and the funding note it returns is
//       real (a leaf the tree actually has) and covers the amount.

import { test } from "node:test";
import assert from "node:assert/strict";

import { commitment, deriveKeypair } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import { H, B } from "@bongtu/core/network";

import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { KeyCache } from "@bongtu/client/keyCache";
import {
  runMergeChain,
  CHAIN_FAILURE_REASSURANCE,
  type RunSpendDeps,
  type SpendContext,
  type SpendIo,
} from "@bongtu/client/spend";
import type { OwnerNote } from "@bongtu/core/indexerApi";
import {
  planDisburseChain,
  pendingLegOf,
  SpendSelectionError,
} from "@bongtu/client/spend";

const SIG = "0x" + "c3".repeat(32) + "d4".repeat(32) + "1b";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;

const selectable = (values: bigint[]) =>
  values.map((v, i) => ({ value: v.toString(), salt: `7${i}`, leafIndex: i, spent: false }));

// ============================== (1) PLAN =====================================

test("a balance whose largest note covers the payroll plans zero merges", () => {
  const plan = planDisburseChain(selectable([900n, 50n, 25n]), "800");
  assert.equal(plan.merges.length, 0);
  assert.equal(plan.funding.value, "900");
  assert.equal(plan.funding.leafIndex, 0);
});

test("a fragmented balance folds its largest notes into the funding note", () => {
  // 4 notes of 250: no single note covers 700, one fold of all four does.
  const plan = planDisburseChain(selectable([250n, 250n, 250n, 250n]), "700");
  assert.equal(plan.merges.length, 1);
  assert.equal(plan.merges[0].inputs.length, 4);
  assert.equal(plan.merges[0].mergedValue, "1000");
  // The funding note is the one the merge will create — pending on leg 0.
  assert.equal(pendingLegOf(plan.funding.leafIndex), 0);
  assert.equal(plan.funding.value, "1000");
});

test("a merge folds at most ten notes, so a wide balance takes several merges", () => {
  // 19 notes of 10: fold 10 -> note(100), then fold [100 + nine 10s] -> note(190).
  const plan = planDisburseChain(selectable(Array.from({ length: 19 }, () => 10n)), "185");
  assert.equal(plan.merges.length, 2);
  assert.equal(plan.merges[0].inputs.length, 10);
  assert.equal(plan.merges[0].mergedValue, "100");
  assert.equal(plan.merges[1].inputs.length, 10);
  assert.equal(plan.merges[1].mergedValue, "190");
  // The second fold spends the first fold's pending note.
  assert.ok(plan.merges[1].inputs.some((n) => pendingLegOf(n.leafIndex) === 0));
  assert.equal(pendingLegOf(plan.funding.leafIndex), 1);
});

test("merging stops the moment one note covers the amount, not at the whole balance", () => {
  // 12 notes of 100: the first fold's note(1000) already covers 950 — the two
  // leftover notes stay unmerged.
  const plan = planDisburseChain(selectable(Array.from({ length: 12 }, () => 100n)), "950");
  assert.equal(plan.merges.length, 1);
  assert.equal(plan.merges[0].mergedValue, "1000");
});

test("not holding the amount is refused BEFORE any merge is planned", () => {
  assert.throws(
    () => planDisburseChain(selectable([100n, 100n]), "500"),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "insufficient",
  );
  assert.throws(
    () => planDisburseChain([], "1"),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "insufficient",
  );
});

test("planning is pure: same notes, same plan, input untouched", () => {
  const notes = selectable([300n, 300n, 300n]);
  const before = JSON.stringify(notes);
  assert.deepEqual(planDisburseChain(notes, "800"), planDisburseChain(notes, "800"));
  assert.equal(JSON.stringify(notes), before);
});

// ============================== (2) RUN ======================================

/** The spendChain.test.ts fake chain+indexer, compacted to what a merge chain
 *  touches: a submit appends the proof's outputs and spends its inputs, and only
 *  then does /notes show the merged note with a real leaf index. */
function chainWorld(values: bigint[]) {
  const tree = new ImtTree(H, B);
  const notes: OwnerNote[] = [];
  const submitted: string[] = [];
  const proved: ProvingRequest[] = [];

  const add = (value: string, salt: string, c: bigint, mine: boolean): void => {
    if (mine) {
      notes.push({
        owner: [SELF[0].toString(), SELF[1].toString()],
        value,
        salt,
        leafIndex: tree.getNextLeafIndex(),
        commitment: c.toString(),
        txHash: "0xseed",
        spent: false,
      });
    }
    tree.appendLeaf(c);
  };
  values.forEach((v, i) =>
    add(v.toString(), (600000n + BigInt(i)).toString(), commitment(v, 600000n + BigInt(i), SELF), true),
  );

  const keyCache = new KeyCache({
    derive: async () => deriveIdentityFromSignature(SIG),
    // The stealth destination reaches these runs pre-derived; the seam is unused.
    deriveStealth: async () => {
      throw new Error("stealth derive must not be reached here");
    },
    currentAccount: async () => "0x1",
    arm: () => () => {},
  });

  interface Output {
    value: string;
    salt: string;
    c: bigint;
    mine: boolean;
  }
  const pending: { current: { spend: string[]; create: Output[] } | null } = { current: null };

  const deps = (over: Partial<RunSpendDeps> = {}): SpendIo => ({
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache,
    getHead: async () => ({ root: tree.getRoot().toString(), nextLeafIndex: tree.getNextLeafIndex() }),
    getSignedPath: async (_url: string, leafIndex: number, ownerCompressed: string) => {
      assert.equal(ownerCompressed, WALLET.compressedPubkey);
      const p = tree.merklePath(leafIndex);
      return {
        leafIndex,
        siblings: p.siblings.map(String),
        pathIndices: p.pathIndices,
        root: tree.getRoot().toString(),
      };
    },
    prove: async (request): Promise<Calldata> => {
      proved.push(request);
      const inp = request.input as unknown as {
        inputCommitments: string[];
        enabled: string[];
        outputCommitments: string[];
        outputValues: string[];
        outputSalts: string[];
        outputOwnerPublicKeys: [string, string][];
      };
      pending.current = {
        spend: inp.inputCommitments.filter((_, i) => inp.enabled[i] === "1"),
        create: inp.outputCommitments.map((c, i) => ({
          value: inp.outputValues[i],
          salt: inp.outputSalts[i],
          c: BigInt(c),
          mine:
            inp.outputOwnerPublicKeys[i][0] === SELF[0].toString() &&
            inp.outputOwnerPublicKeys[i][1] === SELF[1].toString(),
        })),
      };
      return { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };
    },
    submitTransfer10x2: async () => {
      submitted.push("transfer10x2");
      const p = pending.current;
      if (!p) throw new Error("a submit with no proof before it");
      for (const n of notes) if (p.spend.includes(n.commitment)) n.spent = true;
      for (const o of p.create) add(o.value, o.salt, o.c, o.mine);
      pending.current = null;
      return { txHash: `0xmerge${submitted.length}`, explorerUrl: "https://x/tx/merge" };
    },
    // required rail-io members a merge chain must never reach (merges are
    // transfer10x2 only; the terminal disburse is the CALLER's transaction)
    submitTransfer: async () => {
      throw new Error("submitTransfer must not be reached here");
    },
    submitWithdraw: async () => {
      throw new Error("submitWithdraw must not be reached here");
    },
    submitWithdrawRelayed: async () => {
      throw new Error("submitWithdrawRelayed must not be reached here");
    },
    poll: { sleep: async () => {} },
    ...over,
  });

  const ctx = (): SpendContext => ({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: "0x1" } as any,
    indexerUrl: "http://indexer",
    pool: "0x0000000000000000000000000000000000000b0b",
    explorer: "https://x",
    get notes() {
      return notes.filter((n) => !n.spent);
    },
    sessionPubkey: WALLET.compressedPubkey,
    reloadNotes: async () => notes,
  });

  return { tree, notes, submitted, proved, deps, ctx, keyCache };
}

function stageLog(): { on: (s: string, leg: { index: number; count: number }) => void; seen: string[] } {
  const seen: string[] = [];
  return { on: (s, leg) => seen.push(`${s}@${leg.index + 1}/${leg.count}`), seen };
}

test("a covering note means no transactions at all — the funding note is handed straight back", async () => {
  const w = chainWorld([900n, 40n]);
  const log = stageLog();
  const res = await runMergeChain(w.ctx(), "800", log.on, w.deps());
  assert.deepEqual(w.submitted, []);
  assert.deepEqual(log.seen, []);
  assert.equal(res.funding.value, "900");
  assert.equal(res.mergeTxs.length, 0);
  // The note is real: its commitment is a leaf the tree holds at that index.
  const owned = w.notes.find((n) => n.leafIndex === res.funding.leafIndex);
  assert.ok(owned && owned.value === "900" && !owned.spent);
});

test("a fragmented balance runs its merge and returns the note the merge created", async () => {
  const w = chainWorld([250n, 250n, 250n, 250n]);
  const log = stageLog();
  const res = await runMergeChain(w.ctx(), "700", log.on, w.deps());
  assert.deepEqual(w.submitted, ["transfer10x2"]);
  // Legs are numbered over merges + the caller's terminal transaction (1 of 2).
  assert.deepEqual(log.seen, ["unlock@1/2", "assemble@1/2", "prove@1/2", "submit@1/2", "waiting@1/2"]);
  assert.equal(res.funding.value, "1000");
  assert.equal(res.mergeTxs.length, 1);
  // The funding note is the indexer's, with a real leaf, unspent, covering 700.
  const owned = w.notes.find((n) => n.commitment === commitment(1000n, BigInt(res.funding.salt), SELF).toString());
  assert.ok(owned && owned.leafIndex === res.funding.leafIndex && !owned.spent);
  // The merge was a SELF-send: every proved output owner is the wallet itself.
  const inp = w.proved[0].input as unknown as { outputOwnerPublicKeys: [string, string][] };
  for (const [x, y] of inp.outputOwnerPublicKeys) {
    assert.deepEqual([x, y], [SELF[0].toString(), SELF[1].toString()]);
  }
});

test("the second merge spends the note the first one created", async () => {
  const w = chainWorld(Array.from({ length: 19 }, () => 10n));
  const res = await runMergeChain(w.ctx(), "185", () => {}, w.deps());
  assert.deepEqual(w.submitted, ["transfer10x2", "transfer10x2"]);
  const secondInputs = (w.proved[1].input as unknown as { inputCommitments: string[] }).inputCommitments;
  const firstMerged = w.notes.find((n) => n.value === "100");
  assert.ok(firstMerged && secondInputs.includes(firstMerged.commitment));
  assert.equal(res.funding.value, "190");
});

test("a merge that fails says the money did not move and what survived", async () => {
  const w = chainWorld([250n, 250n, 250n, 250n]);
  await assert.rejects(
    runMergeChain(w.ctx(), "700", () => {}, w.deps({
      submitTransfer10x2: async () => {
        throw new Error("boom");
      },
    })),
    (e: Error) => e.message.includes(CHAIN_FAILURE_REASSURANCE),
  );
});
