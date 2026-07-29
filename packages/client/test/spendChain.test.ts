// Headless gate for the wallet's SPEND CHAIN (U-Z2): a payment the circuits cannot
// make in one transaction is planned and run as several — the merges that fold the
// balance down, then the payment itself — with one Confirm in front of the whole
// thing.
//
// This is the wallet's most consequential piece of arithmetic. Get the plan wrong and
// the user either signs transactions they did not need or reaches a leg that cannot be
// built; get the between-legs wait wrong and the payment proves membership for a note
// the tree does not have yet. So both halves are gated separately:
//
//   (1) PLAN — planSpendChain is pure, so the whole decision table is a table test:
//       how many legs, which circuits, which notes each leg folds, and that it stops
//       merging the moment the amount is within reach.
//   (2) RUN — runSpendChain against a fake chain+indexer that behaves like the real
//       pair: a submit appends the transaction's output notes, and the merged note is
//       visible to /notes only afterwards. What is asserted is the order of legs, the
//       stages each reports, and that leg n+1 spends the note leg n created.
//   (3) FAILURE — a chain that breaks partway leaves the money where it was, says so,
//       and is retried as a SHORTER chain, because the merges that landed are real.

import { test } from "node:test";
import assert from "node:assert/strict";

import { commitment, deriveKeypair } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { packPubkey } from "@bongtu/core/pubkey";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";

import { deriveIdentityFromSignature } from "../src/derive.js";
import { KeyCache } from "../src/keyCache.js";
import {
  runSpendChain,
  CHAIN_FAILURE_REASSURANCE,
  MERGE_NOT_INDEXED_MESSAGE,
  type RunSpendDeps,
  type SpendIo,
  type SpendContext,
} from "../src/spendFlow.js";
import type { OwnerNote } from "../src/indexerClient.js";
import {
  legCircuit,
  pendingLegOf,
  planSpendChain,
  SpendSelectionError,
  type SelectableNote,
  type SpendLeg,
} from "../src/spend.js";
import { H, B } from "@bongtu/core/network";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;
const PAYEE_ADDR = packPubkey(deriveKeypair(4242424242424242n).publicKey);

const selectable = (values: bigint[]): SelectableNote[] =>
  values.map((v, i) => ({ value: v.toString(), salt: `9${i}`, leafIndex: i, spent: false }));

/** A plan read the way the confirm sheet reads it: what each transaction does. */
const shape = (legs: SpendLeg[]): string[] =>
  legs.map((l) => `${l.leg}(${l.inputs.length})`);

// ============================== (1) PLAN =====================================

test("a spend that fits one transaction plans one transaction", () => {
  const notes = selectable([100n, 100n, 100n, 100n]);
  assert.deepEqual(shape(planSpendChain("transfer", notes, "150")), ["transfer(2)"]);
  assert.deepEqual(shape(planSpendChain("transfer", notes, "250")), ["transfer10x2(3)"]);
  assert.deepEqual(shape(planSpendChain("withdraw", notes, "150")), ["withdraw(2)"]);
  // the arity boundaries themselves
  assert.deepEqual(shape(planSpendChain("transfer", notes, "200")), ["transfer(2)"]);
  assert.deepEqual(shape(planSpendChain("withdraw", notes, "200")), ["withdraw(2)"]);
  assert.deepEqual(
    shape(planSpendChain("transfer", selectable(Array(10).fill(100n)), "1000")),
    ["transfer10x2(10)"],
    "exactly ten notes is the widest one transaction can do",
  );
});

test("past the arity, the plan grows the merges that make the amount reachable", () => {
  const eleven = selectable(Array(11).fill(100n)); // 1100 across 11 notes
  // 1000 is still one transaction: the ten largest cover it.
  assert.deepEqual(shape(planSpendChain("transfer", eleven, "1000")), ["transfer10x2(10)"]);
  // 1050 is not — so ten notes fold into one, and the payment spends that plus the
  // note left over.
  assert.deepEqual(shape(planSpendChain("transfer", eleven, "1050")), ["merge(10)", "transfer(2)"]);
});

test("merging stops the moment the amount is within reach, not when the notes run out", () => {
  const twenty = selectable(Array(20).fill(100n)); // 2000 across 20 notes
  // an amount the top 19 cover: ONE fold is enough (10 notes become 1, leaving 11,
  // whose largest ten are worth 1900).
  assert.deepEqual(shape(planSpendChain("transfer", twenty, "1900")), [
    "merge(10)",
    "transfer10x2(10)",
  ]);
  // only a near-full-balance spend pays for the second fold — the "3 approvals: 2 to
  // combine, 1 to pay" case the confirm sheet describes.
  assert.deepEqual(shape(planSpendChain("transfer", twenty, "2000")), [
    "merge(10)",
    "merge(10)",
    "transfer(2)",
  ]);
});

test("withdraw, with no arity-10 circuit, folds down to two notes", () => {
  const three = selectable([100n, 100n, 100n]);
  assert.deepEqual(shape(planSpendChain("withdraw", three, "250")), ["merge(3)", "withdraw(1)"]);
  // and a withdraw its two largest notes cover never merges at all
  assert.deepEqual(shape(planSpendChain("withdraw", three, "200")), ["withdraw(2)"]);
});

test("a merge leg folds the LARGEST notes, and the note it will make is worth their total", () => {
  const notes = selectable([50n, 400n, 300n, 200n, 100n, 10n, 20n, 30n, 40n, 60n, 70n]);
  const [first] = planSpendChain("transfer", notes, "1275"); // 1280 total, needs all 11
  assert.equal(first.leg, "merge");
  if (first.leg !== "merge") return;
  assert.deepEqual(
    first.inputs.map((n) => n.value),
    ["400", "300", "200", "100", "70", "60", "50", "40", "30", "20"],
    "largest-first: the 10-value note is the one left out",
  );
  assert.equal(first.mergedValue, "1270");
});

test("the note a merge will create is marked as pending, and named by the leg making it", () => {
  const legs = planSpendChain("transfer", selectable(Array(20).fill(100n)), "2000");
  assert.equal(pendingLegOf(legs[0].inputs[0].leafIndex), null, "leg 1 spends only real notes");
  // leg 2 folds what leg 1 will produce…
  assert.equal(pendingLegOf(legs[1].inputs[0].leafIndex), 0);
  // …and the payment spends what leg 2 will produce.
  assert.equal(pendingLegOf(legs[2].inputs[0].leafIndex), 1);
  assert.deepEqual(legs.map(legCircuit), ["transfer10x2", "transfer10x2", "transfer"]);
});

test("DEPRECATION PIN: no plan, and no merge leg, ever selects transfer10 again", () => {
  // User decision 2026-07-28: transfer10 (10-in/10-out) stays deployed but the
  // wallet must never route to it — merges and >2-input spends are transfer10x2
  // (10-in/2-out). This test sweeps every leg of a representative grid of plans;
  // if legCircuit or planSpendChain ever answers "transfer10", it FAILS.
  const wallets = [
    selectable([100n, 100n, 100n]),
    selectable(Array(10).fill(100n)),
    selectable(Array(11).fill(100n)),
    selectable(Array(20).fill(100n)),
    selectable(Array(35).fill(100n)),
  ];
  for (const notes of wallets) {
    const total = notes.reduce((s, n) => s + BigInt(n.value), 0n);
    for (const kind of ["transfer", "withdraw"] as const) {
      for (const amount of ["250", (total / 2n).toString(), total.toString()]) {
        for (const leg of planSpendChain(kind, notes, amount)) {
          const circuit = legCircuit(leg);
          assert.notEqual(circuit, "transfer10", `deprecated transfer10 resurfaced in ${kind}(${amount})`);
          if (leg.leg === "merge") assert.equal(circuit, "transfer10x2", "a merge is always transfer10x2");
        }
      }
    }
  }
});

test("not holding the amount is still poverty, decided BEFORE any leg is planned", () => {
  const notes = selectable(Array(20).fill(100n));
  assert.throws(
    () => planSpendChain("transfer", notes, "2001"),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "insufficient",
  );
  assert.throws(
    () => planSpendChain("transfer", [], "1"),
    (e: unknown) => e instanceof SpendSelectionError && e.blocker === "insufficient",
  );
  // spent notes are not balance
  const spent = selectable([100n, 100n]).map((n) => ({ ...n, spent: true }));
  assert.throws(() => planSpendChain("transfer", spent, "50"), SpendSelectionError);
  // and a chain is never the answer to a malformed amount
  assert.throws(() => planSpendChain("transfer", notes, "0"), /positive integer/);
});

test("planning is pure: same question, same answer, and the caller's notes are untouched", () => {
  const notes = selectable(Array(20).fill(100n));
  const before = JSON.stringify(notes);
  const a = planSpendChain("transfer", notes, "2000");
  const b = planSpendChain("transfer", notes, "2000");
  assert.deepEqual(a, b);
  assert.equal(JSON.stringify(notes), before, "selection must not reorder or consume the input");
});

// ============================== (2) RUN ======================================

/**
 * A fake chain + arbiter indexer, behaving like the pair the wallet actually talks to:
 * a submitted transaction appends its output notes to the tree and nullifies the notes
 * it spent, and only AFTER that does /notes show the merged note with a leaf index.
 * The outputs come from the proving request, which is what the real contract also
 * reads them from — so a leg that mis-assembles its witness produces a wrong world
 * here too, rather than a world that flatters it.
 */
function chainWorld(values: bigint[]) {
  const tree = new ImtTree(H, B);
  const notes: OwnerNote[] = [];
  const submitted: string[] = [];
  const proved: string[] = [];
  const reloads: number[] = [];

  // Every output commitment becomes a leaf — the contract appends them all, whoever
  // owns them — but only the wallet's own are notes the indexer would show it.
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
    add(v.toString(), (500000n + BigInt(i)).toString(), commitment(v, 500000n + BigInt(i), SELF), true),
  );

  // One page session, one lock: a retry after a failed run reuses the key the first
  // run already paid a signature for.
  const keyCache = new KeyCache({
    derive: async () => deriveIdentityFromSignature(SIG),
    currentAccount: async () => "0x1",
    arm: () => () => {},
  });

  interface Output {
    value: string;
    salt: string;
    c: bigint;
    mine: boolean;
  }
  // What the last proof declared it would do — applied by the matching submit, so the
  // world only changes when a transaction actually goes through.
  let pending: { spend: string[]; create: Output[] } | null = null;

  const record = (request: ProvingRequest): void => {
    const inp = request.input as unknown as {
      inputCommitments: string[];
      enabled: string[];
      outputCommitments: string[];
      outputValues: string[];
      outputSalts: string[];
      outputOwnerPublicKeys: [string, string][];
    };
    proved.push(request.circuit);
    pending = {
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
  };

  const land = (circuit: string) => async (): Promise<{ txHash: string; explorerUrl: string }> => {
    submitted.push(circuit);
    if (!pending) throw new Error("a submit with no proof before it");
    for (const n of notes) if (pending.spend.includes(n.commitment)) n.spent = true;
    for (const o of pending.create) add(o.value, o.salt, o.c, o.mine);
    pending = null;
    return { txHash: `0x${circuit}${submitted.length}`, explorerUrl: `https://x/tx/${circuit}` };
  };

  const deps = (over: Partial<RunSpendDeps> = {}): SpendIo => ({
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache,
    getHead: async () => ({ root: tree.getRoot().toString(), nextLeafIndex: tree.getNextLeafIndex() }),
    getSignedPath: async (_url: string, leafIndex: number, ownerCompressed: string) => {
      // Every membership fetch must be signed AS the spending wallet — the arbiter
      // indexer only opens a batch slot to the leaf's proven owner.
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
      record(request);
      return { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };
    },
    submitTransfer: land("transfer"),
    submitTransfer10x2: land("transfer10x2"),
    submitWithdraw: land("withdraw"),
    poll: { sleep: async () => {} }, // the wait is real; only its seconds are not
    ...over,
  });

  const ctx = (): SpendContext => ({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: "0x1", provider: {}, signer: {} } as any,
    indexerUrl: "http://indexer",
    pool: "0x0000000000000000000000000000000000000b0b",
    explorer: "https://x",
    get notes() {
      return notes.filter((n) => !n.spent);
    },
    sessionPubkey: WALLET.compressedPubkey,
    reloadNotes: async () => {
      reloads.push(notes.length);
      return notes;
    },
  });

  return { tree, notes, submitted, proved, reloads, deps, ctx };
}

/** Every stage a run reports, tagged with the transaction it belonged to. */
function stageLog(): { on: (s: string, leg?: { index: number; count: number }) => void; seen: string[] } {
  const seen: string[] = [];
  return { on: (s, leg) => seen.push(leg ? `${s}@${leg.index + 1}/${leg.count}` : s), seen };
}

test("a one-transaction send runs exactly as it always did", async () => {
  const w = chainWorld([400n, 300n, 200n, 100n]);
  const log = stageLog();
  const out = await runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "800" }, log.on, w.deps());

  assert.deepEqual(w.proved, ["transfer10x2"]);
  assert.deepEqual(w.submitted, ["transfer10x2"]);
  assert.deepEqual(log.seen, ["unlock@1/1", "assemble@1/1", "prove@1/1", "submit@1/1"]);
  assert.deepEqual(w.reloads, [], "nothing to wait for when there is nothing after this");
  assert.equal(out.txHash, "0xtransfer10x21");
});

test("a chained send runs merge, merge, payment — each leg waiting for the one before", async () => {
  const w = chainWorld(Array(20).fill(100n));
  const log = stageLog();
  const out = await runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "2000" }, log.on, w.deps());

  assert.deepEqual(w.proved, ["transfer10x2", "transfer10x2", "transfer"]);
  assert.deepEqual(w.submitted, ["transfer10x2", "transfer10x2", "transfer"]);
  assert.deepEqual(log.seen, [
    "unlock@1/3", "assemble@1/3", "prove@1/3", "submit@1/3", "waiting@1/3",
    // the key is held from here on, so no second signature is asked for or announced
    "assemble@2/3", "prove@2/3", "submit@2/3", "waiting@2/3",
    "assemble@3/3", "prove@3/3", "submit@3/3",
  ]);
  assert.equal(w.reloads.length, 2, "one wait per merge, and none after the payment");
  assert.equal(out.txHash, "0xtransfer3", "the outcome is the PAYMENT, not the last merge");

  // The payment really spent the folded note: every original is nullified, and the
  // wallet is left with the change rather than twenty pieces.
  const unspent = w.notes.filter((n) => !n.spent && BigInt(n.value) > 0n);
  assert.deepEqual(unspent, [], "a full-balance send leaves nothing behind");
});

test("the second merge spends the note the first one created", async () => {
  const w = chainWorld(Array(20).fill(100n));
  await runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "2000" }, () => {}, w.deps());
  // 20 seeds + 2 outputs + 2 outputs + 2 outputs: a merge appends only its merged
  // note and a zero-value change note — the whole point of the 2-out circuit.
  assert.equal(w.tree.getNextLeafIndex(), 26);
  // the note the first merge made is worth the whole fold, and it is spent by the second
  const folded = w.notes.find((n) => n.value === "1000" && n.leafIndex >= 20);
  assert.ok(folded, "the first merge's note reached the indexer");
  assert.equal(folded.spent, true, "and the second merge consumed it");
});

test("a chain the indexer never catches up with stops rather than proving a note that is not there", async () => {
  const w = chainWorld(Array(20).fill(100n));
  const ctx = { ...w.ctx(), reloadNotes: async () => [] }; // /notes never shows the merge
  await assert.rejects(
    runSpendChain("transfer", ctx, { to: PAYEE_ADDR, amount: "2000" }, () => {}, w.deps()),
    new RegExp(MERGE_NOT_INDEXED_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.deepEqual(w.submitted, ["transfer10x2"], "and it does not blindly submit the next leg");
});

// ============================ (3) FAILURE ====================================

test("a leg that fails partway says the money did not move, and what did survive", async () => {
  const w = chainWorld(Array(20).fill(100n));
  const deps = w.deps({
    submitTransfer: async () => {
      throw { code: 4001 }; // the user rejected the PAYMENT, after both merges landed
    },
  });
  await assert.rejects(
    runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "2000" }, () => {}, deps),
    (e: unknown) => {
      const msg = (e as Error).message;
      assert.match(msg, /Transaction rejected in your wallet\./, "the wallet's own words come first");
      assert.ok(msg.includes(CHAIN_FAILURE_REASSURANCE), "followed by what that means for the money");
      return true;
    },
  );
  assert.deepEqual(w.submitted, ["transfer10x2", "transfer10x2"], "the merges stand");
});

test("retrying after a mid-chain failure plans a SHORTER chain, because the merges are real", async () => {
  const w = chainWorld(Array(20).fill(100n));
  const deps = w.deps({
    submitTransfer: async () => {
      throw new Error("network hiccup");
    },
  });
  await assert.rejects(
    runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "2000" }, () => {}, deps),
  );

  // What the form would re-plan from now: the two merges left one 1900 note, one 100
  // note and eighteen value-0 leftovers — two transactions' worth folded into one.
  const replan = planSpendChain("transfer", w.ctx().notes, "2000");
  assert.deepEqual(shape(replan), ["transfer(2)"], "the retry is a single payment");

  const log = stageLog();
  const out = await runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "2000" }, log.on, w.deps());
  assert.deepEqual(log.seen, ["assemble@1/1", "prove@1/1", "submit@1/1"]);
  assert.equal(out.txHash, "0xtransfer3");
});

test("a one-transaction failure is not dressed up as a chain that partly worked", async () => {
  const w = chainWorld([1000n]);
  const deps = w.deps({
    submitTransfer: async () => {
      throw new Error("network hiccup");
    },
  });
  await assert.rejects(
    runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "500" }, () => {}, deps),
    (e: unknown) => {
      assert.equal((e as Error).message, "network hiccup", "the cause reaches the form verbatim");
      return true;
    },
  );

  // …and a raw provider rejection is passed through untouched, for the machine's own
  // walletErrorMessage to translate — wrapping it here would lose the 4001 code.
  const rejected = w.deps({
    submitTransfer: async () => {
      throw { code: 4001 };
    },
  });
  await assert.rejects(
    runSpendChain("transfer", w.ctx(), { to: PAYEE_ADDR, amount: "500" }, () => {}, rejected),
    (e: unknown) => (e as { code?: number }).code === 4001,
  );
});
