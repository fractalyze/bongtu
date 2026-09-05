// Headless gates for the consumer FLOW variants (src/consumerFlows.ts) —
// spendChain.test.ts's fake chain+indexer world, rebuilt for the family whose
// discovery is self-scan: /notes never exists here, so the world's note store
// IS the self-scan result set and reloadNotes is the injected scan pass.
// What is pinned, per the family's delta list:
//   - stage order per flow (the enterprise grammar, unchanged);
//   - the AUTH-FREE path: membership goes through getPath and the signed read /
//     KEM-epoch guard are POISONED seams that throw on contact — the run
//     completing is the proof they were never reached;
//   - the token approve targets the POOL escrow, never a module;
//   - merge planning lands on transfer10x2Priv sealed to SELF, and leg n+1
//     spends the note leg n created (discovered via the scan pass);
//   - the withdraw recipient is proof-bound (connected account by default,
//     withdrawTo substituted);
//   - failure routing: a mid-chain revert surfaces the wallet's classified
//     words + the reassurance; a single-leg failure passes through raw.

import { test } from "node:test";
import assert from "node:assert/strict";

import { commitment } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { H, B } from "@bongtu/core/network";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";

import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { KeyCache } from "@bongtu/client/keyCache";
import type { Connection } from "@bongtu/client/rail";
import { selfConsumerRecipient } from "@bongtu/client/consumer";
import type { ScanNote } from "@bongtu/client/selfscan";
import {
  CHAIN_FAILURE_REASSURANCE,
  MERGE_NOT_INDEXED_MESSAGE,
} from "@bongtu/client/spend";
import {
  consumerRunDeposit,
  consumerRunSpendChain,
  type ConsumerDepositIo,
  type ConsumerSpendContext,
  type ConsumerSpendIo,
} from "@bongtu/client/consumer";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const WALLET = deriveIdentityFromSignature(SIG);
const SELF = WALLET.keypair.publicKey;
const OTHER = deriveIdentityFromSignature("0x" + "c3".repeat(32) + "d4".repeat(32) + "1b");
const PAYEE = selfConsumerRecipient(OTHER);
const CONNECTED = "0x00000000000000000000000000000000000000a1";

const ZERO_CALLDATA: Calldata = { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };

const newKeyCache = (): KeyCache =>
  new KeyCache({
    derive: async () => WALLET,
    deriveStealth: async () => {
      throw new Error("stealth derive must not be reached here");
    },
    currentAccount: async () => CONNECTED,
    arm: () => () => {},
  });

/** Every stage a run reports, tagged with the transaction it belonged to. */
function stageLog(): { on: (s: string, leg?: { index: number; count: number }) => void; seen: string[] } {
  const seen: string[] = [];
  return { on: (s, leg) => seen.push(leg ? `${s}@${leg.index + 1}/${leg.count}` : s), seen };
}

// ========================== the fake consumer world ==========================

/**
 * spendChain.test.ts's chainWorld for the consumer family: a submitted module
 * tx appends its output commitments and nullifies what it spent, and only
 * AFTER that does a self-scan pass (reloadNotes) surface the merged note. The
 * enterprise-only seams — the KEM-epoch guard and the signed path read — are
 * poisoned: touching either fails whichever run reached them.
 */
function consumerWorld(values: bigint[]) {
  const tree = new ImtTree(H, B);
  const notes: ScanNote[] = [];
  const submitted: string[] = [];
  const proved: string[] = [];
  const provedOwners0: [string, string][] = [];
  const reloads: number[] = [];
  const paths: number[] = [];

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

  const keyCache = newKeyCache();

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
    provedOwners0.push(inp.outputOwnerPublicKeys[0]);
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

  const deps = (over: Record<string, unknown> = {}): ConsumerSpendIo =>
    ({
      ensureChain: async () => {},
      keyCache,
      getHead: async () => ({ root: tree.getRoot().toString(), nextLeafIndex: tree.getNextLeafIndex() }),
      // the AUTH-FREE read: (url, leafIndex) only — no owner key, no signature
      getPath: async (_url: string, leafIndex: number) => {
        paths.push(leafIndex);
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
      // POISON: the seams this family removed — reached == failed run.
      assertPoolKemEpoch: () => {
        throw new Error("KEM epoch guard reached in the consumer family");
      },
      getSignedPath: () => {
        throw new Error("signed path read reached — consumer membership is auth-free");
      },
      ...over,
    }) as unknown as ConsumerSpendIo;

  const ctx = (): ConsumerSpendContext => ({
    connection: { address: CONNECTED } as unknown as Connection,
    indexerUrl: "http://indexer",
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

  return { tree, notes, submitted, proved, provedOwners0, reloads, paths, deps, ctx };
}

// =========================== consumerRunDeposit ==============================

function depositWorld(token: { balance: bigint; allowance: bigint }) {
  const approvals: { token: string; spender: string; amount: bigint }[] = [];
  const proved: ProvingRequest[] = [];
  const submits: { kemCts: string[] }[] = [];
  const ctx = {
    connection: { address: CONNECTED } as unknown as Connection,
    pool: "0x000000000000000000000000000000000000b0b0",
    token: "0x000000000000000000000000000000000070ce70",
    explorer: "https://x",
    sessionPubkey: WALLET.compressedPubkey,
  };
  const deps = ({
    ensureChain: async () => {},
    keyCache: newKeyCache(),
    readTokenState: async () => token,
    approveToken: async (_c: Connection, tokenAddr: string, spender: string, amount: bigint) => {
      approvals.push({ token: tokenAddr, spender, amount });
      return "0xapprove";
    },
    prove: async (request: ProvingRequest) => {
      proved.push(request);
      return ZERO_CALLDATA;
    },
    submitDepositPriv: async (_c: Connection, _cd: Calldata, kemCts: string[]) => {
      submits.push({ kemCts });
      return { txHash: "0xdep1", explorerUrl: "https://x/tx/0xdep1" };
    },
    assertPoolKemEpoch: () => {
      throw new Error("KEM epoch guard reached in the consumer family");
    },
  }) as unknown as ConsumerDepositIo;
  return { approvals, proved, submits, ctx, deps };
}

test("consumer deposit: enterprise stage order, approve targets the POOL escrow, no KEM guard, third-party mint", async () => {
  const w = depositWorld({ balance: 10_000n, allowance: 0n });
  const log = stageLog();
  const out = await consumerRunDeposit(w.ctx, { amount: "600", recipient: PAYEE }, log.on, w.deps);

  assert.deepEqual(log.seen, ["unlock", "approve", "prove", "submit"]);
  assert.deepEqual(w.approvals, [{ token: w.ctx.token, spender: w.ctx.pool, amount: 600n }]);
  assert.equal(out.approved, true);
  assert.equal(out.txHash, "0xdep1");

  // the built request is the S2 depositPriv shape: note(V) sealed to the THIRD
  // PARTY's triple, the note(0) companion back to self.
  const inp = w.proved[0].input as unknown as {
    outputValues: string[];
    outputOwnerPublicKeys: [string, string][];
  };
  assert.equal(w.proved[0].circuit, "depositPriv");
  assert.deepEqual(inp.outputValues, ["600", "0"]);
  assert.deepEqual(inp.outputOwnerPublicKeys[0], [
    OTHER.keypair.publicKey[0].toString(),
    OTHER.keypair.publicKey[1].toString(),
  ]);
  assert.deepEqual(inp.outputOwnerPublicKeys[1], [SELF[0].toString(), SELF[1].toString()]);
  // the seals ride the submit as the per-output bytes[] cts
  assert.equal(w.submits[0].kemCts.length, 2);
});

test("consumer deposit: a covering allowance skips the approve tx; an unaffordable amount fails before it", async () => {
  const covered = depositWorld({ balance: 10_000n, allowance: 600n });
  const out = await consumerRunDeposit(covered.ctx, { amount: "600" }, () => {}, covered.deps);
  assert.deepEqual(covered.approvals, [], "no approve when the allowance already covers V");
  assert.equal(out.approved, false);

  const poor = depositWorld({ balance: 100n, allowance: 0n });
  await assert.rejects(consumerRunDeposit(poor.ctx, { amount: "600" }, () => {}, poor.deps));
  assert.deepEqual(poor.approvals, [], "a doomed deposit spends no approve tx");
  assert.deepEqual(poor.proved, [], "…and no proof");

  const corrupt = depositWorld({ balance: 10_000n, allowance: 0n });
  const badTriple = { ...PAYEE, owner: "0xnot-a-point" };
  await assert.rejects(
    consumerRunDeposit(corrupt.ctx, { amount: "600", recipient: badTriple }, () => {}, corrupt.deps),
  );
  assert.deepEqual(corrupt.approvals, [], "a corrupt triple spends no approve tx either");
});

// ========================== consumerRunSpendChain ============================

test("a one-transaction consumer send: stage order, auth-free membership, transferPriv to the payee triple", async () => {
  const w = consumerWorld([400n, 300n]);
  const log = stageLog();
  const out = await consumerRunSpendChain("transfer", w.ctx(), { to: PAYEE, amount: "600" }, log.on, w.deps());

  assert.deepEqual(w.proved, ["transferPriv"]);
  assert.deepEqual(w.submitted, ["transferPriv"]);
  assert.deepEqual(log.seen, ["unlock@1/1", "assemble@1/1", "prove@1/1", "submit@1/1"]);
  assert.deepEqual(w.paths, [0, 1], "each input's membership came through the OPEN /path read");
  assert.deepEqual(
    w.provedOwners0[0],
    [OTHER.keypair.publicKey[0].toString(), OTHER.keypair.publicKey[1].toString()],
    "the payment output seals to the recipient triple",
  );
  assert.deepEqual(w.reloads, [], "nothing to scan for when there is nothing after this");
  assert.equal(out.txHash, "0xtransferPriv1");
});

test("a consumer chain merges via transfer10x2Priv-to-self, and each leg spends what the scan pass found", async () => {
  const w = consumerWorld(Array(20).fill(100n));
  const log = stageLog();
  const out = await consumerRunSpendChain("transfer", w.ctx(), { to: PAYEE, amount: "2000" }, log.on, w.deps());

  assert.deepEqual(w.proved, ["transfer10x2Priv", "transfer10x2Priv", "transferPriv"]);
  assert.deepEqual(w.submitted, ["transfer10x2Priv", "transfer10x2Priv", "transferPriv"]);
  assert.deepEqual(log.seen, [
    "unlock@1/3", "assemble@1/3", "prove@1/3", "submit@1/3", "waiting@1/3",
    "assemble@2/3", "prove@2/3", "submit@2/3", "waiting@2/3",
    "assemble@3/3", "prove@3/3", "submit@3/3",
  ]);
  // merges seal their fold to SELF (self-scan is how the wallet re-finds them)
  const self = [SELF[0].toString(), SELF[1].toString()];
  assert.deepEqual(w.provedOwners0.slice(0, 2), [self, self]);
  assert.equal(w.reloads.length, 2, "one self-scan wait per merge, none after the payment");
  assert.equal(out.txHash, "0xtransferPriv3", "the outcome is the PAYMENT, not the last merge");

  // the second merge really spent the first merge's note
  const folded = w.notes.find((n) => n.value === "1000" && n.leafIndex >= 20);
  assert.ok(folded, "the first merge's note was discovered by scan");
  assert.equal(folded.spent, true, "and the second merge consumed it");
  const unspent = w.notes.filter((n) => !n.spent && BigInt(n.value) > 0n);
  assert.deepEqual(unspent, [], "a full-balance send leaves nothing behind");
});

test("a consumer withdraw binds the payout in-proof: the connected account by default, withdrawTo substituted", async () => {
  const recipients: bigint[] = [];
  const spy = (w: ReturnType<typeof consumerWorld>): ConsumerSpendIo => {
    const base = w.deps();
    return w.deps({
      prove: async (request: ProvingRequest) => {
        if (request.circuit === "withdrawPriv") {
          recipients.push(BigInt((request.input as unknown as { recipient: string }).recipient));
        }
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        return base.prove!(request);
      },
    });
  };

  const byDefault = consumerWorld([100n, 100n, 100n]);
  await consumerRunSpendChain("withdraw", byDefault.ctx(), { amount: "250" }, () => {}, spy(byDefault));
  assert.deepEqual(byDefault.submitted, ["transfer10x2Priv", "withdrawPriv"], "merge then the proof-bound exit");

  const DEST = "0x00000000000000000000000000000000000d0001";
  const substituted = consumerWorld([100n, 100n]);
  await consumerRunSpendChain("withdraw", substituted.ctx(), { amount: "150", withdrawTo: DEST }, () => {}, spy(substituted));

  assert.deepEqual(recipients, [BigInt(CONNECTED), BigInt(DEST)]);
});

test("a chain the self-scan never finds the merged note in stops rather than proving a phantom", async () => {
  const w = consumerWorld(Array(20).fill(100n));
  const ctx = { ...w.ctx(), reloadNotes: async (): Promise<ScanNote[]> => [] };
  await assert.rejects(
    consumerRunSpendChain("transfer", ctx, { to: PAYEE, amount: "2000" }, () => {}, w.deps()),
    new RegExp(MERGE_NOT_INDEXED_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.deepEqual(w.submitted, ["transfer10x2Priv"], "and it does not blindly submit the next leg");
});

test("failure routing: a mid-chain revert gets the wallet's words + the reassurance; a single leg passes raw", async () => {
  const midChain = consumerWorld(Array(20).fill(100n));
  const rejecting = midChain.deps({
    submitTransferPriv: async () => {
      throw { code: 4001 }; // the user rejected the PAYMENT after both merges landed
    },
  });
  await assert.rejects(
    consumerRunSpendChain("transfer", midChain.ctx(), { to: PAYEE, amount: "2000" }, () => {}, rejecting),
    (e: unknown) => {
      const msg = (e as Error).message;
      assert.match(msg, /Transaction rejected in your wallet\./, "the classified verdict comes first");
      assert.ok(msg.includes(CHAIN_FAILURE_REASSURANCE), "followed by what that means for the money");
      return true;
    },
  );
  assert.deepEqual(midChain.submitted, ["transfer10x2Priv", "transfer10x2Priv"], "the merges stand");

  const single = consumerWorld([1000n]);
  const reverting = single.deps({
    submitTransferPriv: async () => {
      throw new Error("execution reverted: InvalidProof()");
    },
  });
  await assert.rejects(
    consumerRunSpendChain("transfer", single.ctx(), { to: PAYEE, amount: "500" }, () => {}, reverting),
    (e: unknown) => {
      assert.equal((e as Error).message, "execution reverted: InvalidProof()", "the revert reaches the form verbatim");
      return true;
    },
  );

  // …and a transfer with no recipient triple is refused before anything is planned or signed
  const guard = consumerWorld([1000n]);
  await assert.rejects(
    consumerRunSpendChain("transfer", guard.ctx(), { amount: "500" }, () => {}, guard.deps()),
    /registered consumer triple/,
  );
  assert.deepEqual(guard.proved, [], "no proof, no submit, no membership read");
});
