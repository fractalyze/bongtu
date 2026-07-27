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

import { ActionMachine, stepsForRun, type ActionResult } from "../src/ui/actionMachine.js";
import { SPEND_STEPS, DEPOSIT_STEPS } from "../src/ui/components/StagedProgress.js";

const OUTCOME: ActionResult = {
  txHash: `0x${"ab".repeat(32)}`,
  explorerUrl: `https://sepolia-explorer.giwa.io/tx/0x${"ab".repeat(32)}`,
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
