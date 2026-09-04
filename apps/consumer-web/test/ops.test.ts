// Interface-level gates for the S6 op screens, all driven from ONE shared fake
// world (the S5 fake-scan world extended with flow fakes: an in-memory tree,
// module submits that append what was proven, and a reload that IS the scan
// pass). The REAL engine flows (consumerRunDeposit / consumerRunSpendChain) run
// through the app's REAL ActionMachine, so every row below is the sequence a
// screen would actually repaint:
//
//   (1) PER-OP STAGE TABLES — deposit (approve skipped when covered), send
//       (single leg and a merge chain with the waiting stage), withdraw (the
//       proof-bound payout, defaulted and substituted).
//   (2) ONE-OP-AT-A-TIME — the OpGate invariant, including release on failure
//       (a machine is never stranded holding the slot).
//   (3) MID-OP ACCOUNT SWITCH — the S5 guard locks; the next leg's unlock
//       refuses; the machine lands back on the form with the classified words
//       plus the chain reassurance, and the gate is free again.
//   (4) AMOUNT VERDICTS — the engine's parseKkrw words reach the form verbatim,
//       one row per cause.
//   (5) FAILURE COPY — the app's table covers every ChainFailure kind.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { ImtTree } from "@bongtu/core/imt";
import { H, B } from "@bongtu/core/network";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { ChainFailure } from "@bongtu/core/errors";
import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { KeyCache } from "@bongtu/client/keyCache";
import type { Connection } from "@bongtu/client/connection";
import { selfConsumerRecipient } from "@bongtu/client/consumerBuild";
import { ACCOUNT_MISMATCH_MESSAGE } from "@bongtu/client/identity";
import type { ScanNote } from "@bongtu/client/selfscan";
import { parseKkrw } from "@bongtu/client/money";
import { CHAIN_FAILURE_REASSURANCE, type SpendOutcome } from "@bongtu/client/spendFlow";
import {
  consumerRunDeposit,
  consumerRunSpendChain,
  type ConsumerDepositIo,
  type ConsumerDepositOutcome,
  type ConsumerSpendContext,
  type ConsumerSpendIo,
} from "@bongtu/client/consumerFlows";

import {
  ActionMachine,
  OpGate,
  OP_IN_FLIGHT_MESSAGE,
  stepsForRun,
  type ActionResult,
} from "../src/ui/actionMachine.js";
import {
  SPEND_STEPS,
  DEPOSIT_STEPS,
  activeStep,
  chainSteps,
} from "../src/ui/components/StagedProgress.js";
import { CONSUMER_FAILURE_COPY, consumerErrorMessage } from "../src/lib/errors.js";
import { amountError } from "../src/ui/format.js";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;
const OTHER = deriveIdentityFromSignature("0x" + "c3".repeat(32) + "d4".repeat(32) + "1b");
const PAYEE = selfConsumerRecipient(OTHER);
const CONNECTED = "0x00000000000000000000000000000000000000a1";
const SWITCHED = "0x00000000000000000000000000000000000000b2";
const CONN = { address: CONNECTED } as unknown as Connection;

const ZERO_CALLDATA: Calldata = { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };

/** Every snapshot the screen would repaint on, phase:stage@leg/count. */
function recordMachine<O extends ActionResult>(m: ActionMachine<O>): string[] {
  const seen: string[] = [];
  m.subscribe(() => {
    const s = m.snapshot();
    seen.push(`${s.phase}:${s.stage}@${s.legIndex + 1}/${s.legCount}`);
  });
  return seen;
}

// ===================== the ONE shared fake consumer world ====================

/** The S5 scan world grown flow edges: a submitted module tx appends its output
 *  commitments and nullifies what it spent, and reloadNotes IS the scan pass
 *  that then finds the merged note. `account.current` is the live wallet's
 *  selected account — flip it to play the S5 switch guard against a chain. */
function consumerWorld(values: bigint[]) {
  const tree = new ImtTree(H, B);
  const notes: ScanNote[] = [];
  const submitted: string[] = [];
  const account = { current: CONNECTED };
  const keyCache = new KeyCache({
    // the real derivation follows the wallet's CURRENT account, which is what
    // makes a post-switch unlock produce the WRONG identity and refuse
    derive: async () => (account.current === CONNECTED ? WALLET : OTHER),
    deriveStealth: async () => {
      throw new Error("stealth derive must not be reached by an op");
    },
    currentAccount: async () => account.current,
    arm: () => () => {},
  });

  const add = (value: string, salt: string, c: bigint, mine: boolean): void => {
    if (mine) {
      notes.push({
        value,
        salt,
        leafIndex: tree.getNextLeafIndex(),
        commitment: c.toString(),
        nullifier: `n${tree.getNextLeafIndex()}`,
        txHash: "0xseed",
        spent: false,
        seq: notes.length,
        kind: "depositPriv",
        family: "consumer",
      });
    }
    tree.appendLeaf(c);
  };
  const seed = async (): Promise<void> => {
    const { commitment } = await import("@bongtu/core/note");
    values.forEach((v, i) =>
      add(v.toString(), (500000n + BigInt(i)).toString(), commitment(v, 500000n + BigInt(i), SELF), true),
    );
  };

  interface Output {
    value: string;
    salt: string;
    c: bigint;
    mine: boolean;
  }
  const pending: { current: { spend: string[]; create: Output[] } | null } = { current: null };
  const withdrawRecipients: bigint[] = [];

  const record = (request: ProvingRequest): void => {
    const inp = request.input as unknown as {
      inputCommitments: string[];
      enabled: string[];
      outputCommitments: string[];
      outputValues: string[];
      outputSalts: string[];
      outputOwnerPublicKeys: [string, string][];
      recipient?: string;
    };
    if (request.circuit === "withdrawPriv" && inp.recipient !== undefined) {
      withdrawRecipients.push(BigInt(inp.recipient));
    }
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
  };

  const land = (circuit: string) => async (): Promise<{ txHash: string; explorerUrl: string }> => {
    submitted.push(circuit);
    const p = pending.current;
    if (!p) throw new Error("a submit with no proof before it");
    for (const n of notes) if (p.spend.includes(n.commitment)) n.spent = true;
    for (const o of p.create) add(o.value, o.salt, o.c, o.mine);
    pending.current = null;
    return { txHash: `0x${circuit}${submitted.length}`, explorerUrl: `https://x/tx/${circuit}` };
  };

  const deps = (): ConsumerSpendIo =>
    ({
      ensureChain: async () => {},
      keyCache,
      getHead: async () => ({ root: tree.getRoot().toString(), nextLeafIndex: tree.getNextLeafIndex() }),
      getPath: async (_url: string, leafIndex: number) => {
        const p = tree.merklePath(leafIndex);
        return {
          leafIndex,
          siblings: p.siblings.map(String),
          pathIndices: p.pathIndices,
          root: tree.getRoot().toString(),
        };
      },
      prove: async (request: ProvingRequest): Promise<Calldata> => {
        record(request);
        return ZERO_CALLDATA;
      },
      submitTransferPriv: land("transferPriv"),
      submitTransfer10x2Priv: land("transfer10x2Priv"),
      submitWithdrawPriv: land("withdrawPriv"),
      poll: { sleep: async () => {} },
    }) as unknown as ConsumerSpendIo;

  const ctx = (over: Partial<ConsumerSpendContext> = {}): ConsumerSpendContext => ({
    connection: CONN,
    indexerUrl: "http://indexer",
    explorer: "https://x",
    get notes() {
      return notes.filter((n) => !n.spent);
    },
    sessionPubkey: WALLET.compressedPubkey,
    reloadNotes: async () => notes,
    ...over,
  });

  return { notes, submitted, withdrawRecipients, account, keyCache, deps, ctx, seed };
}

function depositWorld(token: { balance: bigint; allowance: bigint }) {
  const approvals: { token: string; spender: string; amount: bigint }[] = [];
  const keyCache = new KeyCache({
    derive: async () => WALLET,
    deriveStealth: async () => {
      throw new Error("stealth derive must not be reached by an op");
    },
    currentAccount: async () => CONNECTED,
    arm: () => () => {},
  });
  const ctx = {
    connection: CONN,
    pool: "0x000000000000000000000000000000000000b0b0",
    token: "0x000000000000000000000000000000000070ce70",
    explorer: "https://x",
    sessionPubkey: WALLET.compressedPubkey,
  };
  const deps = ({
    ensureChain: async () => {},
    keyCache,
    readTokenState: async () => token,
    approveToken: async (_c: Connection, tokenAddr: string, spender: string, amount: bigint) => {
      approvals.push({ token: tokenAddr, spender, amount });
      return "0xapprove";
    },
    prove: async () => ZERO_CALLDATA,
    submitDepositPriv: async () => ({ txHash: "0xdep1", explorerUrl: "https://x/tx/0xdep1" }),
  }) as unknown as ConsumerDepositIo;
  return { approvals, ctx, deps, keyCache };
}

// ======================= (1) PER-OP STAGE TABLES =============================

test("deposit stage table: locked run shows unlock → approve → prove → submit; the unlock step joins the rail", async () => {
  const w = depositWorld({ balance: 10_000n, allowance: 0n });
  const m = new ActionMachine<ConsumerDepositOutcome>(DEPOSIT_STEPS[0].key, new OpGate());
  const seen = recordMachine(m);

  await m.submit(
    (onStage) => consumerRunDeposit(w.ctx, { amount: "600", recipient: PAYEE }, onStage, w.deps),
    () => {},
  );

  assert.deepEqual(seen, [
    "running:approve@1/1",
    "running:unlock@1/1",
    "running:approve@1/1",
    "running:prove@1/1",
    "running:submit@1/1",
    "done:submit@1/1",
  ]);
  assert.deepEqual(
    stepsForRun(DEPOSIT_STEPS, m.snapshot().unlocking).map((s) => s.key),
    ["unlock", "approve", "prove", "submit"],
  );
  assert.deepEqual(w.approvals, [{ token: w.ctx.token, spender: w.ctx.pool, amount: 600n }]);
  assert.equal(m.snapshot().outcome?.approved, true);
});

test("deposit stage table: an unlocked wallet with a covering allowance shows no unlock and sends no approve tx", async () => {
  const w = depositWorld({ balance: 10_000n, allowance: 600n });
  await w.keyCache.unlock(CONN, WALLET.compressedPubkey);
  const m = new ActionMachine<ConsumerDepositOutcome>(DEPOSIT_STEPS[0].key, new OpGate());
  const seen = recordMachine(m);

  await m.submit((onStage) => consumerRunDeposit(w.ctx, { amount: "600" }, onStage, w.deps), () => {});

  assert.deepEqual(seen, [
    "running:approve@1/1",
    "running:approve@1/1",
    "running:prove@1/1",
    "running:submit@1/1",
    "done:submit@1/1",
  ]);
  assert.equal(m.snapshot().unlocking, false, "no signature step the user is not asked for");
  assert.deepEqual(w.approvals, []);
  assert.equal(m.snapshot().outcome?.approved, false);
});

test("send stage table, single leg: assemble → prove → submit at 1 of 1", async () => {
  const w = consumerWorld([400n, 300n]);
  await w.seed();
  await w.keyCache.unlock(CONN, WALLET.compressedPubkey);
  const m = new ActionMachine<SpendOutcome>(SPEND_STEPS[0].key, new OpGate());
  const seen = recordMachine(m);

  await m.submit(
    (onStage) => consumerRunSpendChain("transfer", w.ctx(), { to: PAYEE, amount: "600" }, onStage, w.deps()),
    () => {},
  );

  assert.deepEqual(seen, [
    "running:assemble@1/1",
    "running:assemble@1/1",
    "running:prove@1/1",
    "running:submit@1/1",
    "done:submit@1/1",
  ]);
  assert.deepEqual(w.submitted, ["transferPriv"]);
});

test("send stage table, chain: merge legs surface as legs, the self-scan wait as its own stage", async () => {
  const w = consumerWorld(Array(20).fill(100n));
  await w.seed();
  await w.keyCache.unlock(CONN, WALLET.compressedPubkey);
  const m = new ActionMachine<SpendOutcome>(SPEND_STEPS[0].key, new OpGate());
  const seen = recordMachine(m);

  await m.submit(
    (onStage) => consumerRunSpendChain("transfer", w.ctx(), { to: PAYEE, amount: "2000" }, onStage, w.deps()),
    () => {},
  );

  assert.deepEqual(seen, [
    "running:assemble@1/1", // submit opens before the flow says how long the chain is
    "running:assemble@1/3",
    "running:prove@1/3",
    "running:submit@1/3",
    "running:waiting@1/3",
    "running:assemble@2/3",
    "running:prove@2/3",
    "running:submit@2/3",
    "running:waiting@2/3",
    "running:assemble@3/3",
    "running:prove@3/3",
    "running:submit@3/3",
    "done:submit@3/3",
  ]);
  assert.deepEqual(w.submitted, ["transfer10x2Priv", "transfer10x2Priv", "transferPriv"]);

  // The screen mapping the RunningPanel renders from: a chain's steps are its
  // transactions, and the waiting stage describes the leg it belongs to.
  assert.deepEqual(chainSteps(3, "Sending").map((s) => s.key), ["leg0", "leg1", "leg2"]);
  assert.deepEqual(activeStep({ stage: "waiting", legIndex: 0, legCount: 3 }), {
    stage: "leg0",
    describeKey: "waiting",
  });
  assert.deepEqual(activeStep({ stage: "unlock", legIndex: 0, legCount: 3 }), {
    stage: "unlock",
    describeKey: "unlock",
  });
});

test("withdraw stage table: the payout is proof-bound — connected account by default, withdrawTo substituted", async () => {
  const byDefault = consumerWorld([100n, 100n]);
  await byDefault.seed();
  await byDefault.keyCache.unlock(CONN, WALLET.compressedPubkey);
  const m = new ActionMachine<SpendOutcome>(SPEND_STEPS[0].key, new OpGate());
  const seen = recordMachine(m);
  await m.submit(
    (onStage) => consumerRunSpendChain("withdraw", byDefault.ctx(), { amount: "150" }, onStage, byDefault.deps()),
    () => {},
  );
  assert.deepEqual(seen, [
    "running:assemble@1/1",
    "running:assemble@1/1",
    "running:prove@1/1",
    "running:submit@1/1",
    "done:submit@1/1",
  ]);
  assert.deepEqual(byDefault.submitted, ["withdrawPriv"]);
  assert.deepEqual(byDefault.withdrawRecipients, [BigInt(CONNECTED)]);

  const DEST = "0x00000000000000000000000000000000000d0001";
  const substituted = consumerWorld([100n, 100n]);
  await substituted.seed();
  await substituted.keyCache.unlock(CONN, WALLET.compressedPubkey);
  const m2 = new ActionMachine<SpendOutcome>(SPEND_STEPS[0].key, new OpGate());
  await m2.submit(
    (onStage) =>
      consumerRunSpendChain("withdraw", substituted.ctx(), { amount: "150", withdrawTo: DEST }, onStage, substituted.deps()),
    () => {},
  );
  assert.deepEqual(substituted.withdrawRecipients, [BigInt(DEST)]);
});

// ========================= (2) ONE-OP-AT-A-TIME ==============================

test("exactly one op runs at a time: a second submit refuses with the pinned copy and never starts its run", async () => {
  const gate = new OpGate();
  const a = new ActionMachine<ActionResult>(SPEND_STEPS[0].key, gate);
  const b = new ActionMachine<ActionResult>(DEPOSIT_STEPS[0].key, gate);
  const release: { fire: () => void } = { fire: () => {} };
  const first = a.submit(
    () =>
      new Promise((resolve) => {
        release.fire = () =>
          resolve({ txHash: "0x1", explorerUrl: "https://x/tx/0x1" });
      }),
    () => {},
  );

  const bRan = { current: false };
  await b.submit(async () => {
    bRan.current = true;
    return { txHash: "0x2", explorerUrl: "https://x/tx/0x2" };
  }, () => {});

  assert.equal(bRan.current, false, "the refused op's flow never runs");
  assert.equal(b.snapshot().phase, "form");
  assert.equal(b.snapshot().error, OP_IN_FLIGHT_MESSAGE);
  assert.equal(a.snapshot().phase, "running", "the running op is untouched by the refusal");

  release.fire();
  await first;
  assert.equal(a.snapshot().phase, "done");
  assert.equal(gate.busy(), false, "the slot frees the moment the run ends");

  await b.submit(async () => ({ txHash: "0x2", explorerUrl: "https://x/tx/0x2" }), () => {});
  assert.equal(b.snapshot().phase, "done", "the next op runs once the slot is free");
});

test("a failed run releases the slot: no machine is ever stranded holding it", async () => {
  const gate = new OpGate();
  const m = new ActionMachine<ActionResult>(SPEND_STEPS[0].key, gate);
  await m.submit(async () => {
    throw new Error("boom");
  }, () => {});
  assert.equal(m.snapshot().phase, "form");
  assert.equal(gate.busy(), false);
});

// ======================== (3) MID-OP ACCOUNT SWITCH ==========================

test("a mid-chain account switch aborts safely: back on the form with the words + reassurance, gate free, no stranded stage", async () => {
  const w = consumerWorld(Array(20).fill(100n));
  await w.seed();
  await w.keyCache.unlock(CONN, WALLET.compressedPubkey);
  const gate = new OpGate();
  const m = new ActionMachine<SpendOutcome>(SPEND_STEPS[0].key, gate);

  // The switch, played as the S5 guard plays it: during the between-legs scan
  // wait the wallet's selected account changes and the guard locks the key.
  const flipped = { current: false };
  const ctx = w.ctx({
    reloadNotes: async () => {
      if (!flipped.current) {
        flipped.current = true;
        w.account.current = SWITCHED;
        w.keyCache.lock();
      }
      return w.notes;
    },
  });

  await m.submit(
    (onStage) => consumerRunSpendChain("transfer", ctx, { to: PAYEE, amount: "2000" }, onStage, w.deps()),
    () => {},
  );

  const s = m.snapshot();
  assert.equal(s.phase, "form", "the abort lands where the user can act, never mid-rail");
  assert.equal(s.error, `${ACCOUNT_MISMATCH_MESSAGE} ${CHAIN_FAILURE_REASSURANCE}`);
  assert.equal(s.outcome, null);
  assert.deepEqual(w.submitted, ["transfer10x2Priv"], "the switched account signed nothing");
  assert.equal(gate.busy(), false, "the abort released the one-op slot");

  await m.submit(async () => ({ txHash: "0x3", explorerUrl: "https://x/tx/0x3" }), () => {});
  assert.equal(m.snapshot().phase, "done", "the machine is fully reusable after the abort");
});

// ========================== (4) AMOUNT VERDICTS ==============================

test("amount verdicts pass the engine's words through verbatim, one row per cause", () => {
  const engineRows = ["", "1,5", "abc", ".", "1.1234567", "2000000000000"];
  for (const raw of engineRows) {
    const p = parseKkrw(raw);
    assert.ok(!p.ok, `${JSON.stringify(raw)} must fail the parse`);
    assert.equal(amountError(raw, null), p.error, `engine words verbatim for ${JSON.stringify(raw)}`);
  }
  // the two verdicts owned above the parser: positivity and the balance fit
  assert.equal(amountError("0", null), "Amount must be greater than zero.");
  assert.equal(amountError("2", 10n ** 18n), "Amount exceeds your balance.");
  assert.equal(amountError("2", 10n ** 18n, "Amount exceeds your kKRW balance."), "Amount exceeds your kKRW balance.");
  // a valid amount inside the balance passes
  assert.equal(amountError("1", 10n ** 18n), null);
  // a null balance cannot judge over-spend (the screens keep their own guard)
  assert.equal(amountError("2", null), null);
});

// =========================== (5) FAILURE COPY ================================

test("the consumer copy table covers every ChainFailure kind, each with words", () => {
  assert.deepEqual(Object.keys(CONSUMER_FAILURE_COPY).sort(), [
    "chain_switch",
    "insufficient_gas",
    "other",
    "timeout",
    "transport",
    "user_rejected",
  ]);
  for (const [kind, words] of Object.entries(CONSUMER_FAILURE_COPY)) {
    for (const rejected of [true, false]) {
      const failure = { kind, rejected, text: "engine line" } as unknown as ChainFailure;
      const message = (words as (f: ChainFailure, e: unknown) => string)(failure, new Error("engine line"));
      assert.ok(message.length > 0, `${kind} has words`);
    }
  }
});

test("failure routing: rejection reads plainly, a declined switch names the network, the engine line passes through", () => {
  assert.equal(consumerErrorMessage({ code: 4001 }), "Transaction rejected in your wallet.");
  const declined = { kind: "chain_switch", rejected: true, text: null } as unknown as ChainFailure;
  assert.match(CONSUMER_FAILURE_COPY.chain_switch(declined as never, declined), /Network switch rejected/);
  const failed = { kind: "chain_switch", rejected: false, text: null } as unknown as ChainFailure;
  assert.match(CONSUMER_FAILURE_COPY.chain_switch(failed as never, failed), /Could not switch/);
  // `other` must not paraphrase: the flows' own wrapped lines (reassurance
  // included) reach the screen untouched.
  assert.equal(consumerErrorMessage(new Error("Nothing was sent. boom")), "Nothing was sent. boom");
});

// ============== the page-wide gate default + S6 review wiring pins ===========

test("machines default onto the page's ONE gate: two default-built machines contend", async () => {
  // The cross-screen invariant lives in the constructor's default gate — a
  // machine built without an explicit gate must land on the shared slot, or
  // every screen quietly gets its own gate and the suite above proves nothing
  // about the page.
  const a = new ActionMachine<ActionResult>("assemble");
  const b = new ActionMachine<ActionResult>("assemble");
  const held = { release: (): void => {} };
  const first = a.submit(
    () =>
      new Promise<ActionResult>((resolve) => {
        held.release = () => resolve({ txHash: "0xa", explorerUrl: "ea" });
      }),
    () => {},
  );
  await b.submit(async () => ({ txHash: "0xb", explorerUrl: "eb" }), () => {});
  assert.equal(b.snapshot().error, OP_IN_FLIGHT_MESSAGE);
  held.release();
  await first;
  assert.equal(a.snapshot().phase, "done");
});

const src = (rel: string): string => readFileSync(new URL(rel, import.meta.url).pathname, "utf8");

// CONVENTION NOTE (the S5 rule): SOURCE presence pins are a flagged compromise
// for hook/JSX bodies no headless render reaches — they pin the wiring's
// shape, not its execution. The absence scan below is the durable kind.
test("S6 wiring pins: running back-guard, register takes the op slot, reloadNotes fails fast on a locked key", () => {
  assert.match(src("../src/ui/components/ActionPanels.tsx"), /<Panel title=\{title\} backDisabled>/);
  assert.match(src("../src/ui/screens/Receive.tsx"), /opGate\.tryAcquire\(/);
  assert.match(src("../src/ui/App.tsx"), /keyCache\.peek\(session\.compressedPubkey\) === null/);
});

test("resolve failures render classified words, never the raw thrown message", () => {
  for (const rel of [
    "../src/ui/screens/SpendScreen.tsx",
    "../src/ui/screens/Deposit.tsx",
    "../src/ui/screens/Receive.tsx",
  ]) {
    assert.doesNotMatch(src(rel), /e instanceof Error \? e\.message/, `${rel} renders a raw message`);
  }
});
