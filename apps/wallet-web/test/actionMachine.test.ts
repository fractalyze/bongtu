// Headless gate for the phase machine every value-moving screen runs (src/ui/
// actionMachine.ts). This is the wallet's largest behavioural surface — form → confirm
// → running → done, the unlock step, the error landing, the post-action refresh — and
// it used to be reachable only by scanning the screen sources as text. The machine
// takes the flow as an ARGUMENT, so everything below drives it with a stub run and
// asserts the snapshots the screens render from.
//
// The React adapter (useActionMachine) adds no decisions of its own: it subscribes to
// this object and calls stepsForRun, which is exercised directly here.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { EXPLORER_BASE } from "@bongtu/core/network";
import { ActionMachine, OpGate, OP_IN_FLIGHT_MESSAGE, stepsForRun, type ActionResult } from "../src/ui/actionMachine.js";
import { SPEND_STEPS, DEPOSIT_STEPS } from "../src/ui/components/StagedProgress.js";

// Arbitrary fixture — the machine passes explorerUrl through without parsing it.
// Sourced from the sdk so a chain move needs no edit here.
const OUTCOME: ActionResult = {
  txHash: `0x${"ab".repeat(32)}`,
  explorerUrl: `${EXPLORER_BASE}/tx/0x${"ab".repeat(32)}`,
};

/** A flow that reports `stages` in order, then succeeds. */
function reports(...stages: string[]) {
  return async (onStage: (stage: string) => void): Promise<ActionResult> => {
    for (const s of stages) onStage(s);
    return OUTCOME;
  };
}

/** A flow that fails the way the wallet fails — the thrown value, verbatim. */
function fails(e: unknown) {
  return async (): Promise<ActionResult> => {
    throw e;
  };
}

/** Records every snapshot the screen would repaint on, so the assertions can read the
 *  run as it happened rather than only where it ended. */
function recorder(machine: ActionMachine<ActionResult>): () => string[] {
  const seen: string[] = [];
  machine.subscribe(() => {
    const s = machine.snapshot();
    seen.push(`${s.phase}:${s.stage}`);
  });
  return () => seen;
}

function spendMachine(): ActionMachine<ActionResult> {
  return new ActionMachine<ActionResult>(SPEND_STEPS[0].key);
}

// ======================= (1) THE PHASES =====================================

test("a fresh machine sits on the form, already on the flow's first stage", () => {
  const m = spendMachine();
  assert.deepEqual(m.snapshot(), {
    phase: "form",
    stage: "assemble",
    legIndex: 0,
    legCount: 1,
    unlocking: false,
    error: null,
    outcome: null,
  });
  // deposit's flow opens on its own first stage — the machine takes it from the steps
  assert.equal(new ActionMachine(DEPOSIT_STEPS[0].key).snapshot().stage, "approve");
});

test("Continue reviews, Cancel goes back", () => {
  const m = spendMachine();
  m.review();
  assert.equal(m.snapshot().phase, "confirm");
  m.cancel();
  assert.equal(m.snapshot().phase, "form");
});

test("the happy path walks confirm → running → done and keeps the outcome", async () => {
  const m = spendMachine();
  const seen = recorder(m);
  const refreshed: string[] = [];

  m.review();
  await m.submit(reports("assemble", "prove", "submit"), (tx) => refreshed.push(tx));

  assert.deepEqual(seen(), [
    "confirm:assemble",
    "running:assemble", // submit opens on the first stage, before the flow says anything
    "running:assemble",
    "running:prove",
    "running:submit",
    "done:submit",
  ]);
  const s = m.snapshot();
  assert.equal(s.phase, "done");
  assert.equal(s.outcome, OUTCOME, "the success panel links THIS run's transaction");
  assert.equal(s.error, null);
  assert.deepEqual(refreshed, [OUTCOME.txHash], "the indexer poll runs once, on the tx hash");
});

test("a hung post-action refresh does not hold the success screen back", async () => {
  const m = spendMachine();
  // The poll takes up to 30s; the user must be on the done screen long before that.
  await m.submit(reports("prove"), () => new Promise(() => {}));
  assert.equal(m.snapshot().phase, "done");
});

// ======================= (2) THE UNLOCK STEP ================================

test("the unlock step appears only for a run that asks for the signature", async () => {
  const locked = spendMachine();
  await locked.submit(reports("unlock", "assemble", "prove", "submit"), () => {});
  assert.equal(locked.snapshot().unlocking, true);
  const lockedSteps = stepsForRun(SPEND_STEPS, locked.snapshot().unlocking);
  assert.deepEqual(
    lockedSteps.map((s) => s.key),
    ["unlock", "assemble", "prove", "submit"],
  );

  const held = spendMachine();
  await held.submit(reports("assemble", "prove", "submit"), () => {});
  assert.equal(held.snapshot().unlocking, false, "a wallet already holding the key asks for nothing");
  assert.deepEqual(
    stepsForRun(SPEND_STEPS, held.snapshot().unlocking).map((s) => s.key),
    ["assemble", "prove", "submit"],
    "and the list never grows a step the user is not asked to do",
  );
  assert.equal(SPEND_STEPS.length, 3, "stepsForRun copies — the shared list is not mutated");
});

test("the unlock step from a previous run does not linger", async () => {
  const m = spendMachine();
  await m.submit(reports("unlock", "assemble"), () => {});
  assert.equal(m.snapshot().unlocking, true);
  // second action of the session: the key is held now, so no signature is asked for
  await m.submit(reports("assemble", "prove"), () => {});
  assert.equal(m.snapshot().unlocking, false);
});

// ======================= (3) THE ERROR LANDING ==============================

test("a failed run lands back on the form with the wallet's own message", async () => {
  const m = spendMachine();
  const refreshed: string[] = [];
  m.review();
  await m.submit(fails(new Error("Your balance just changed — go back and try again.")), (tx) =>
    refreshed.push(tx),
  );

  const s = m.snapshot();
  assert.equal(s.phase, "form", "the form is where the user can act on the failure");
  assert.equal(s.error, "Your balance just changed — go back and try again.");
  assert.equal(s.outcome, null, "nothing succeeded, so no success panel and no explorer link");
  assert.deepEqual(refreshed, [], "and nothing to poll the indexer for");
});

test("a rejected signature reads as a rejection, not as a raw provider object", async () => {
  const m = spendMachine();
  await m.submit(fails({ code: 4001 }), () => {});
  assert.equal(m.snapshot().error, "Transaction rejected in your wallet.");
});

test("reviewing again clears the last failure, and the retry starts clean", async () => {
  const m = spendMachine();
  await m.submit(fails(new Error("boom")), () => {});
  assert.equal(m.snapshot().error, "boom");

  m.review();
  assert.equal(m.snapshot().error, null, "the banner does not follow the user into the confirm sheet");

  await m.submit(reports("assemble", "prove", "submit"), () => {});
  assert.equal(m.snapshot().phase, "done");
  assert.equal(m.snapshot().error, null);
});

// ======================= (3b) MULTI-TRANSACTION RUNS ========================
// A spend whose balance is too scattered to pay in one go runs as several
// transactions (spendFlow.runSpendChain). The machine carries which one is in flight
// so the screen can count them off; a flow that reports no leg keeps 0 of 1, which is
// every deposit and every plain send.

test("a flow that reports no leg stays a single transaction", async () => {
  const m = spendMachine();
  await m.submit(reports("assemble", "prove", "submit"), () => {});
  assert.equal(m.snapshot().legIndex, 0);
  assert.equal(m.snapshot().legCount, 1);
});

test("a chained run carries which transaction is in flight, and how many there are", async () => {
  const m = spendMachine();
  const seen: string[] = [];
  m.subscribe(() => {
    const s = m.snapshot();
    seen.push(`${s.phase}:${s.stage}@${s.legIndex + 1}/${s.legCount}`);
  });

  const chain = async (onStage: (s: string, leg?: { index: number; count: number }) => void) => {
    for (const index of [0, 1]) {
      const leg = { index, count: 3 };
      for (const s of ["assemble", "prove", "submit", "waiting"]) onStage(s, leg);
    }
    for (const s of ["assemble", "prove", "submit"]) onStage(s, { index: 2, count: 3 });
    return OUTCOME;
  };
  const refreshed: string[] = [];
  await m.submit(chain, (tx) => refreshed.push(tx));

  assert.deepEqual(seen, [
    "running:assemble@1/1", // submit opens before the flow has said how long the chain is
    "running:assemble@1/3",
    "running:prove@1/3",
    "running:submit@1/3",
    "running:waiting@1/3", // …the indexer catching up is a stage of its own
    "running:assemble@2/3",
    "running:prove@2/3",
    "running:submit@2/3",
    "running:waiting@2/3",
    "running:assemble@3/3",
    "running:prove@3/3",
    "running:submit@3/3",
    "done:submit@3/3",
  ]);
  assert.deepEqual(
    refreshed,
    [OUTCOME.txHash],
    "ONE post-action refresh, on the terminal transaction: the between-legs waits are " +
      "the chain's own business, and refreshing per leg would poll for money that has " +
      "not moved yet",
  );
});

test("the next run starts from one transaction again, whatever the last one took", async () => {
  const m = spendMachine();
  await m.submit(async (onStage) => {
    onStage("submit", { index: 1, count: 2 });
    return OUTCOME;
  }, () => {});
  assert.equal(m.snapshot().legCount, 2);

  await m.submit(reports("assemble", "prove", "submit"), () => {});
  assert.equal(m.snapshot().legCount, 1, "a plain send does not inherit the last chain's length");
  assert.equal(m.snapshot().legIndex, 0);
});

// ======================= (4) REPAINTS =======================================

test("every transition publishes a NEW snapshot, so a subscribed screen repaints", async () => {
  const m = spendMachine();
  const snapshots: unknown[] = [];
  const stop = m.subscribe(() => snapshots.push(m.snapshot()));
  m.review();
  await m.submit(reports("prove"), () => {});
  stop();
  assert.ok(snapshots.length >= 4);
  assert.equal(new Set(snapshots).size, snapshots.length, "identity changes on every publish");

  const after = snapshots.length;
  m.cancel();
  assert.equal(snapshots.length, after, "and an unsubscribed screen stops hearing about it");
});

// ======================= (5) ONE MACHINE, NOT THREE =========================

test("the action screens run the shared machine instead of hand-rolling the phases", () => {
  const dir = new URL("../src/ui/screens/", import.meta.url).pathname;
  for (const file of ["SpendScreen.tsx", "Deposit.tsx"]) {
    const text = readFileSync(`${dir}${file}`, "utf8");
    assert.match(text, /useActionMachine/, `${file} no longer goes through the shared machine`);
    for (const hand of [/setPhase/, /useState<Phase>/, /setUnlocking/, /walletErrorMessage/]) {
      assert.doesNotMatch(text, hand, `${file} is re-growing a phase machine of its own`);
    }
  }
});

// ======================= (6) ONE-OP-AT-A-TIME ===============================
// The gate consumer-web added (two wallet popups interleaving over one lock is
// the confusion the guard exists to prevent) now guards this wallet too
// (issue #45). Pure-machine cases; each test owns its gate.

test("exactly one op runs at a time: a second submit refuses with the pinned copy and never starts its run", async () => {
  assert.equal(
    OP_IN_FLIGHT_MESSAGE,
    "Another action is still running. Let it finish before starting a new one.",
  );
  const gate = new OpGate();
  const a = new ActionMachine<ActionResult>(SPEND_STEPS[0].key, gate);
  const b = new ActionMachine<ActionResult>(DEPOSIT_STEPS[0].key, gate);
  const release: { fire: () => void } = { fire: () => {} };
  const first = a.submit(
    () =>
      new Promise((resolve) => {
        release.fire = () => resolve(OUTCOME);
      }),
    () => {},
  );

  const bRan = { current: false };
  await b.submit(async () => {
    bRan.current = true;
    return OUTCOME;
  }, () => {});

  assert.equal(bRan.current, false, "the refused op's flow never runs");
  assert.equal(b.snapshot().phase, "form");
  assert.equal(b.snapshot().error, OP_IN_FLIGHT_MESSAGE);
  assert.equal(a.snapshot().phase, "running", "the running op is untouched by the refusal");

  release.fire();
  await first;
  assert.equal(a.snapshot().phase, "done");
  assert.equal(gate.busy(), false, "the slot frees the moment the run ends");

  await b.submit(async () => OUTCOME, () => {});
  assert.equal(b.snapshot().phase, "done", "the next op runs once the slot is free");
});

test("a failed run releases the slot: no machine is ever stranded holding it", async () => {
  const gate = new OpGate();
  const m = new ActionMachine<ActionResult>(SPEND_STEPS[0].key, gate);
  await m.submit(fails(new Error("boom")), () => {});
  assert.equal(m.snapshot().phase, "form");
  assert.equal(gate.busy(), false);
});
