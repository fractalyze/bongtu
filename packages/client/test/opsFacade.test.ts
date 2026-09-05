// Interface gates for the bound-op facades (ops/spend SpendOps, ops/consumer
// ConsumerOps — issue #34, the C1 bind-once precedent). What is pinned:
//
//   - BIND-ONCE + DELEGATION: constructing ONCE over injected fakes and calling
//     methods hits the SAME free-fn paths the flow suites pin — the same stage
//     grammar, the same submits, the same guard order — and a second call
//     reuses the same bound deps (no per-call re-threading).
//   - STRUCTURAL LOCK SEAM: the flows' keyCache dep is the KeyCacheLike
//     interface, so a plain-object fake typechecks with NO cast and no class.
//   - NOTE SOURCE SEAM: preview plans over noteSource.notes(); a spend is
//     planned from exactly those notes (an unaffordable amount is refused
//     before any IO); and the between-legs wait reloads THROUGH the seam.

import { test } from "node:test";
import assert from "node:assert/strict";

import { commitment } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { H, B } from "@bongtu/core/network";
import type { OwnerNote } from "@bongtu/core/indexerApi";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";

import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import type { Connection } from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import type { ScanNote } from "@bongtu/client/selfscan";
import {
  ConsumerOps,
  selfConsumerRecipient,
  type ConsumerOpsDeps,
  type RunConsumerDepositDeps,
  type RunConsumerSpendDeps,
} from "@bongtu/client/consumer";
import {
  SpendOps,
  previewSpend,
  type RunSpendDeps,
  type SpendOpsDeps,
} from "@bongtu/client/spend";
import type { RunDepositDeps } from "@bongtu/client/deposit";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;
const OTHER = deriveIdentityFromSignature("0x" + "c3".repeat(32) + "d4".repeat(32) + "1b");
const PAYEE = selfConsumerRecipient(OTHER);
const CONNECTED = "0x00000000000000000000000000000000000000a1";
const CONN = { address: CONNECTED } as unknown as Connection;

const ZERO_CALLDATA: Calldata = { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };

const SESSION = { compressedPubkey: WALLET.compressedPubkey };

/** The structural seam's whole point: a plain object, assigned to KeyCacheLike
 *  with NO cast — if the flows still demanded the concrete class, this file
 *  would not compile. */
function fakeLock(): KeyCacheLike & { unlocks: { connection: Connection; sessionPubkey: string }[] } {
  const unlocks: { connection: Connection; sessionPubkey: string }[] = [];
  return {
    unlocks,
    isUnlocked: () => true,
    unlock: async (connection: Connection, sessionPubkey: string) => {
      unlocks.push({ connection, sessionPubkey });
      return WALLET;
    },
  };
}

function stageLog(): { on: (s: string, leg?: { index: number; count: number }) => void; seen: string[] } {
  const seen: string[] = [];
  return { on: (s, leg) => seen.push(leg ? `${s}@${leg.index + 1}/${leg.count}` : s), seen };
}

// ============================ ConsumerOps ====================================

/** consumerFlows.test.ts's fake world, driven THROUGH the facade: a submitted
 *  module tx appends its output commitments and nullifies what it spent, and
 *  noteSource.reload IS the scan pass that then surfaces the merged note. */
function consumerFacade(values: bigint[]) {
  const tree = new ImtTree(H, B);
  const notes: ScanNote[] = [];
  const submitted: string[] = [];
  const proved: string[] = [];
  const reloads: number[] = [];
  const approvals: { token: string; spender: string; amount: bigint }[] = [];
  const lock = fakeLock();

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
  values.forEach((v, i) =>
    add(v.toString(), (500000n + BigInt(i)).toString(), commitment(v, 500000n + BigInt(i), SELF), true),
  );

  interface Output {
    value: string;
    salt: string;
    c: bigint;
    mine: boolean;
  }
  const pending: { current: { spend: string[]; create: Output[] } | null } = { current: null };

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
    pending.current = {
      spend: (inp.inputCommitments ?? []).filter((_, i) => inp.enabled[i] === "1"),
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

  // The io fakes ride the SAME deps object the required half lives on — the
  // facade spreads it into the flows' io seam, which is what the delegation
  // assertions below observe.
  const io = {
    ensureChain: async () => {},
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
    readTokenState: async () => ({ balance: 10_000n, allowance: 0n }),
    approveToken: async (_c: Connection, tokenAddr: string, spender: string, amount: bigint) => {
      approvals.push({ token: tokenAddr, spender, amount });
      return "0xapprove";
    },
    submitDepositPriv: land("depositPriv"),
    submitTransferPriv: land("transferPriv"),
    submitTransfer10x2Priv: land("transfer10x2Priv"),
    submitWithdrawPriv: land("withdrawPriv"),
    poll: { sleep: async () => {} },
  } as unknown as Pick<
    RunConsumerSpendDeps,
    "ensureChain" | "submitTransferPriv" | "submitTransfer10x2Priv" | "submitWithdrawPriv"
  > &
    Pick<RunConsumerDepositDeps, "readTokenState" | "approveToken" | "submitDepositPriv"> &
    Partial<RunConsumerSpendDeps> &
    Partial<RunConsumerDepositDeps>;

  const deps: ConsumerOpsDeps = {
    connection: CONN,
    indexerUrl: "http://indexer",
    pool: "0x000000000000000000000000000000000000b0b0",
    token: "0x000000000000000000000000000000000070ce70",
    explorer: "https://x",
    keyCache: lock, // the plain-object fake, no cast (KeyCacheLike is structural)
    prove: async (request: ProvingRequest): Promise<Calldata> => {
      record(request);
      return ZERO_CALLDATA;
    },
    ...io,
  };

  const ops = new ConsumerOps(deps, SESSION, {
    notes: () => notes.filter((n) => !n.spent),
    reload: async () => {
      reloads.push(notes.length);
      return notes;
    },
  });

  return { ops, deps, lock, notes, submitted, proved, reloads, approvals };
}

test("ConsumerOps.deposit delegates to consumerRunDeposit over the bound deps, and binds ONCE across calls", async () => {
  const w = consumerFacade([]);
  const log = stageLog();
  const out = await w.ops.deposit({ amount: "600", recipient: PAYEE }, log.on);

  // the free-fn suite's exact stage grammar and pool-escrow approve
  assert.deepEqual(log.seen, ["approve", "prove", "submit"]);
  assert.deepEqual(w.approvals, [{ token: w.deps.token, spender: w.deps.pool, amount: 600n }]);
  assert.equal(out.approved, true);
  assert.deepEqual(w.proved, ["depositPriv"]);

  // bind-once: a SECOND call on the same construction reuses the same bound
  // connection + session pubkey — nothing was re-threaded per call.
  await w.ops.deposit({ amount: "700" }, () => {});
  assert.deepEqual(w.proved, ["depositPriv", "depositPriv"]);
  assert.equal(w.lock.unlocks.length, 2);
  for (const u of w.lock.unlocks) {
    assert.equal(u.connection, w.deps.connection);
    assert.equal(u.sessionPubkey, SESSION.compressedPubkey);
  }
});

test("ConsumerOps.spend delegates to consumerRunSpendChain, and the merge wait reloads THROUGH the note source", async () => {
  const w = consumerFacade(Array(20).fill(100n));
  const log = stageLog();
  const out = await w.ops.spend("transfer", { to: PAYEE, amount: "2000" }, log.on);

  // the free-fn suite's chain: two transfer10x2Priv merges, then the payment
  assert.deepEqual(w.submitted, ["transfer10x2Priv", "transfer10x2Priv", "transferPriv"]);
  assert.deepEqual(log.seen, [
    "assemble@1/3", "prove@1/3", "submit@1/3", "waiting@1/3",
    "assemble@2/3", "prove@2/3", "submit@2/3", "waiting@2/3",
    "assemble@3/3", "prove@3/3", "submit@3/3",
  ]);
  assert.equal(w.reloads.length, 2, "the between-legs wait re-read via noteSource.reload, once per merge");
  assert.equal(out.txHash, "0xtransferPriv3");
});

test("ConsumerOps: preview and spend plan over noteSource.notes() — an unaffordable spend is refused before any IO", async () => {
  const w = consumerFacade([500n]);
  assert.deepEqual(
    w.ops.preview("transfer", "300"),
    previewSpend("transfer", w.notes, "300"),
    "preview IS previewSpend over the source's notes",
  );
  await assert.rejects(w.ops.spend("transfer", { to: PAYEE, amount: "9999" }, () => {}));
  assert.deepEqual(w.proved, [], "refused at planning: no proof");
  assert.equal(w.lock.unlocks.length, 0, "…and no unlock — nothing was signed for a doomed spend");
});

// ============================== SpendOps =====================================

function spendFacade(values: bigint[]) {
  const lock = fakeLock();
  const submits: { pool: string; connection: Connection }[] = [];
  const approvals: { token: string; spender: string; amount: bigint }[] = [];
  const proved: string[] = [];
  const reloads: number[] = [];
  const notes: OwnerNote[] = values.map((v, i) => ({
    owner: [SELF[0].toString(), SELF[1].toString()],
    value: v.toString(),
    salt: (600000n + BigInt(i)).toString(),
    leafIndex: i,
    commitment: commitment(v, 600000n + BigInt(i), SELF).toString(),
    txHash: "0xseed",
    spent: false,
  }));

  const io = {
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    readTokenState: async () => ({ balance: 10_000n, allowance: 0n }),
    approveToken: async (_c: Connection, tokenAddr: string, spender: string, amount: bigint) => {
      approvals.push({ token: tokenAddr, spender, amount });
      return "0xapprove";
    },
    submitDeposit: async (connection: Connection, pool: string) => {
      submits.push({ pool, connection });
      return { txHash: "0xdep", explorerUrl: "https://x/tx/0xdep" };
    },
    getHead: async () => {
      throw new Error("SENTINEL: membership read reached");
    },
    // required rail-io members the deposit-only paths must never reach
    submitTransfer: async () => {
      throw new Error("submitTransfer must not be reached here");
    },
    submitTransfer10x2: async () => {
      throw new Error("submitTransfer10x2 must not be reached here");
    },
    submitWithdraw: async () => {
      throw new Error("submitWithdraw must not be reached here");
    },
    submitWithdrawRelayed: async () => {
      throw new Error("submitWithdrawRelayed must not be reached here");
    },
  } as unknown as Pick<
    RunSpendDeps,
    | "ensureChain"
    | "assertPoolKemEpoch"
    | "submitTransfer"
    | "submitTransfer10x2"
    | "submitWithdraw"
    | "submitWithdrawRelayed"
  > &
    Pick<RunDepositDeps, "readTokenState" | "approveToken" | "submitDeposit"> &
    Partial<RunSpendDeps> &
    Partial<RunDepositDeps>;

  const deps: SpendOpsDeps = {
    connection: CONN,
    indexerUrl: "http://indexer",
    pool: "0x000000000000000000000000000000000000b0b0",
    token: "0x000000000000000000000000000000000070ce70",
    explorer: "https://x",
    keyCache: lock, // the plain-object fake, no cast (KeyCacheLike is structural)
    prove: async (request: ProvingRequest): Promise<Calldata> => {
      proved.push(request.circuit);
      return ZERO_CALLDATA;
    },
    ...io,
  };

  const ops = new SpendOps(deps, SESSION, {
    notes: () => notes.filter((n) => !n.spent),
    reload: async () => {
      reloads.push(notes.length);
      return notes;
    },
  });

  return { ops, deps, lock, notes, submits, approvals, proved, reloads };
}

test("SpendOps.deposit delegates to runDeposit over the bound deps (stage grammar, exact-V approve, bound pool)", async () => {
  const w = spendFacade([]);
  const log = stageLog();
  const out = await w.ops.deposit({ amount: "600" }, log.on);

  assert.deepEqual(log.seen, ["approve", "prove", "submit"]);
  assert.deepEqual(w.approvals, [{ token: w.deps.token, spender: w.deps.pool, amount: 600n }]);
  assert.deepEqual(w.proved, ["deposit"]);
  assert.equal(out.approved, true);
  assert.deepEqual(w.submits, [{ pool: w.deps.pool, connection: w.deps.connection }]);
  assert.deepEqual(w.lock.unlocks, [{ connection: w.deps.connection, sessionPubkey: SESSION.compressedPubkey }]);
});

test("SpendOps.spend delegates to runSpendChain: guards pass over the bound deps, then the injected read is hit", async () => {
  const w = spendFacade([1000n]);
  // the sentinel getHead proves the call travelled the free-fn path (session
  // guards first, then fetchMemberships) with THIS construction's fakes.
  await assert.rejects(
    w.ops.spend("transfer", { to: WALLET.compressedPubkey, amount: "600" }, () => {}),
    /SENTINEL: membership read reached/,
  );
  assert.deepEqual(w.lock.unlocks, [{ connection: w.deps.connection, sessionPubkey: SESSION.compressedPubkey }]);
  assert.deepEqual(w.proved, [], "nothing proves past a failed membership read");
});

test("SpendOps: preview plans over noteSource.notes()", () => {
  const w = spendFacade([400n, 300n, 200n]);
  assert.deepEqual(w.ops.preview("transfer", "850"), previewSpend("transfer", w.notes, "850"));
  assert.deepEqual(w.ops.preview("withdraw", "999999"), previewSpend("withdraw", w.notes, "999999"));
});
