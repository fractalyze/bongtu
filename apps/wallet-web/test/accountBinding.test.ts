// Headless gate for the spending key's SESSION BINDING as the two action flows see it
// (lib/identity.ts + lib/keyCache.ts, enforced in spendFlow.runSpend and
// depositFlow.runDeposit). The lock's own state machine — reuse, both idle-wipe
// layers, the indicator — is gated in keyCache.test.ts; this file is about what the
// FLOWS do with it.
//
// A derivation resolves whatever account MetaMask has selected at the time — the
// ethers signer follows the extension, not the stored session — so switching accounts
// mid-session would otherwise hand the flow a different person's bjj key. What is
// gated here:
//
//   (1) PREDICATE — assertSessionIdentity accepts only the session's own key, and is
//       insensitive to hex case / stray whitespace (the same key written two ways).
//   (2) SPEND — a mismatched key aborts runSpend before ANY indexer read, proof or
//       submit happens (for transfer AND withdraw).
//   (3) DEPOSIT — a mismatched key aborts runDeposit before the approve tx, the proof
//       and the submit.
//   (4) MATCHING — the same flows complete normally when the key does match, so the
//       guard is not simply blocking everything.
//   (5) LOCK ACROSS ACTIONS — the first action unlocks (one signature) and reports the
//       "unlock" stage; the next action reuses the key, derives nothing and skips that
//       stage; an account switch between them blocks both flows; signing out re-locks.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { Calldata } from "@bongtu/core/proving";
import { commitment } from "@bongtu/core/note";
import { ImtTree, foldToRoot } from "@bongtu/core/imt";
import { deriveIdentityFromSignature } from "../src/lib/derive.js";
import { ACCOUNT_MISMATCH_MESSAGE, assertSessionIdentity } from "../src/lib/identity.js";
import { KeyCache } from "../src/lib/keyCache.js";
import { runSpend, type RunSpendDeps, type SpendContext } from "../src/lib/spendFlow.js";
import { runDeposit, type DepositContext, type RunDepositDeps } from "../src/lib/depositFlow.js";
import type { OwnerNote } from "../src/lib/indexerClient.js";

const SESSION_SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const OTHER_SIG = "0x" + "c3".repeat(32) + "d4".repeat(32) + "1b";
const SESSION = deriveIdentityFromSignature(SESSION_SIG);
const OTHER = deriveIdentityFromSignature(OTHER_SIG);

const ACCOUNT = "0x0000000000000000000000000000000000000001";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const FAKE_CONNECTION = { address: ACCOUNT, provider: {}, signer: {} } as any;

const DUMMY_CALLDATA: Calldata = { a: ["0", "0"], b: [["0", "0"], ["0", "0"]], c: ["0", "0"], pub: [] };

// One note big enough for the amounts below, owned by the session key, sitting at
// leaf 0 of an otherwise-empty tree — so the membership fold in buildSpendInputs
// actually reaches the root the fake /head serves and the happy path is a REAL
// pass, not a membership failure that happens to come after the guard.
const NOTE_COMMITMENT = commitment(1000n, 7n, SESSION.keypair.publicKey);
const EMPTY_SIBLINGS = new ImtTree().zeros.slice(0, 32).map((z) => z.toString());
const MEMBERSHIP_ROOT = foldToRoot(NOTE_COMMITMENT, EMPTY_SIBLINGS, 0).toString();

const NOTES: OwnerNote[] = [
  {
    owner: [SESSION.keypair.publicKey[0].toString(), SESSION.keypair.publicKey[1].toString()],
    value: "1000",
    salt: "7",
    leafIndex: 0,
    commitment: NOTE_COMMITMENT.toString(),
    txHash: "0xdep",
    spent: false,
  },
];

/** Counters for every I/O edge that must NOT run once the guard fires. */
interface Trace {
  derive: number;
  head: number;
  path: number;
  prove: number;
  submit: number;
  approve: number;
}
const newTrace = (): Trace => ({ derive: 0, head: 0, path: 0, prove: 0, submit: 0, approve: 0 });

/** What MetaMask would answer during a test: which account is selected, and which
 *  signature (hence which bjj key) a derivation would produce. Mutable, so a test can
 *  switch accounts between two actions the way a user does. */
interface FakeWallet {
  sig: string;
  account: string;
}
const sessionWallet = (): FakeWallet => ({ sig: SESSION_SIG, account: ACCOUNT });

/** One page session's lock, wired to the trace's derive counter. The idle timer is a
 *  no-op here — its behaviour is keyCache.test.ts's subject, not this file's. */
function testCache(trace: Trace, wallet: FakeWallet): KeyCache {
  return new KeyCache({
    derive: async () => {
      trace.derive++;
      return deriveIdentityFromSignature(wallet.sig);
    },
    currentAccount: async () => wallet.account,
    arm: () => () => {},
  });
}

function spendDeps(trace: Trace, keyCache: KeyCache): Partial<RunSpendDeps> {
  return {
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache,
    getHead: async () => {
      trace.head++;
      return { root: MEMBERSHIP_ROOT, nextLeafIndex: 1 };
    },
    getPath: async () => {
      trace.path++;
      return {
        leafIndex: 0,
        siblings: EMPTY_SIBLINGS,
        pathIndices: Array.from({ length: 32 }, () => 0),
        root: MEMBERSHIP_ROOT,
      };
    },
    proveInBrowser: async () => {
      trace.prove++;
      return DUMMY_CALLDATA;
    },
    submitTransfer: async () => {
      trace.submit++;
      return { txHash: "0xtransfer", explorerUrl: "https://x/tx/0xtransfer" };
    },
    submitWithdraw: async () => {
      trace.submit++;
      return { txHash: "0xwithdraw", explorerUrl: "https://x/tx/0xwithdraw" };
    },
  };
}

const spendCtx = (): SpendContext => ({
  connection: FAKE_CONNECTION,
  indexerUrl: "http://localhost:8600",
  notes: NOTES,
  sessionPubkey: SESSION.compressedPubkey,
});

function depositDeps(trace: Trace, keyCache: KeyCache): Partial<RunDepositDeps> {
  return {
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache,
    readTokenState: async () => ({ balance: 10_000n, allowance: 0n }),
    approveToken: async () => {
      trace.approve++;
      return "0xapprove";
    },
    proveInBrowser: async () => {
      trace.prove++;
      return DUMMY_CALLDATA;
    },
    submitDeposit: async () => {
      trace.submit++;
      return { txHash: "0xdeposit", explorerUrl: "https://x/tx/0xdeposit" };
    },
  };
}

const depositCtx = (): DepositContext => ({
  connection: FAKE_CONNECTION,
  sessionPubkey: SESSION.compressedPubkey,
});

// ============================ (1) PREDICATE ==================================

test("assertSessionIdentity accepts only the session's key, case- and space-insensitively", () => {
  assert.doesNotThrow(() => assertSessionIdentity(SESSION.compressedPubkey, SESSION.compressedPubkey));
  assert.doesNotThrow(() =>
    assertSessionIdentity(SESSION.compressedPubkey.toUpperCase(), ` ${SESSION.compressedPubkey} `),
  );
  assert.throws(
    () => assertSessionIdentity(OTHER.compressedPubkey, SESSION.compressedPubkey),
    new RegExp(ACCOUNT_MISMATCH_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.notEqual(SESSION.compressedPubkey, OTHER.compressedPubkey, "the two fixtures must be distinct keys");
});

// ============================ (2) SPEND ======================================

for (const kind of ["transfer", "withdraw"] as const) {
  test(`runSpend (${kind}) aborts on a switched account before any read, proof or submit`, async () => {
    const trace = newTrace();
    const wallet: FakeWallet = { sig: OTHER_SIG, account: ACCOUNT };
    await assert.rejects(
      runSpend(
        kind,
        spendCtx(),
        { to: OTHER.compressedPubkey, amount: "100" },
        () => {},
        spendDeps(trace, testCache(trace, wallet)),
      ),
      new RegExp(ACCOUNT_MISMATCH_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
    assert.equal(trace.derive, 1, "the key is derived once — that is how the mismatch is detected");
    assert.equal(trace.head, 0, "no indexer read may happen under a foreign key");
    assert.equal(trace.path, 0, "no membership witness may be fetched under a foreign key");
    assert.equal(trace.prove, 0, "no proof may be built under a foreign key");
    assert.equal(trace.submit, 0, "no tx may be submitted under a foreign key");
  });
}

// ============================ (3) DEPOSIT ====================================

test("runDeposit aborts on a switched account before the approve tx, proof or submit", async () => {
  const trace = newTrace();
  const wallet: FakeWallet = { sig: OTHER_SIG, account: ACCOUNT };
  await assert.rejects(
    runDeposit(depositCtx(), { amount: "100" }, () => {}, depositDeps(trace, testCache(trace, wallet))),
    new RegExp(ACCOUNT_MISMATCH_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.equal(trace.derive, 1);
  assert.equal(trace.approve, 0, "an account switch must not cost the user an approve tx");
  assert.equal(trace.prove, 0);
  assert.equal(trace.submit, 0);
});

// ============================ (4) MATCHING ===================================

test("the same flows complete when the derived key IS the session's", async () => {
  const spendTrace = newTrace();
  const spent = await runSpend(
    "withdraw",
    spendCtx(),
    { amount: "100" },
    () => {},
    spendDeps(spendTrace, testCache(spendTrace, sessionWallet())),
  );
  assert.equal(spent.txHash, "0xwithdraw");
  assert.equal(spendTrace.submit, 1);

  const depTrace = newTrace();
  const deposited = await runDeposit(
    depositCtx(),
    { amount: "100" },
    () => {},
    depositDeps(depTrace, testCache(depTrace, sessionWallet())),
  );
  assert.equal(deposited.txHash, "0xdeposit");
  assert.equal(depTrace.approve, 1);
  assert.equal(depTrace.submit, 1);
});

// ============================ (5) LOCK ACROSS ACTIONS ========================

test("one signature covers a whole page session: action 2 reuses the key and skips the unlock stage", async () => {
  const trace = newTrace();
  const cache = testCache(trace, sessionWallet());

  const first: string[] = [];
  await runSpend("withdraw", spendCtx(), { amount: "100" }, (s) => first.push(s), spendDeps(trace, cache));
  assert.equal(trace.derive, 1, "the first action pays the one signature");
  assert.deepEqual(first, ["unlock", "assemble", "prove", "submit"], "and the user is told why");

  const second: string[] = [];
  await runSpend("withdraw", spendCtx(), { amount: "100" }, (s) => second.push(s), spendDeps(trace, cache));
  assert.equal(trace.derive, 1, "the second action derives NOTHING — no second popup");
  assert.deepEqual(second, ["assemble", "prove", "submit"], "and shows no stage the user isn't asked to do");

  // A deposit on the same page session rides the same unlocked wallet.
  const third: string[] = [];
  await runDeposit(depositCtx(), { amount: "100" }, (s) => third.push(s), depositDeps(trace, cache));
  assert.equal(trace.derive, 1);
  assert.deepEqual(third, ["approve", "prove", "submit"]);
});

test("an account switch between two actions blocks the second one in both flows", async () => {
  const wallet = sessionWallet();
  const trace = newTrace();
  const cache = testCache(trace, wallet);
  await runSpend("withdraw", spendCtx(), { amount: "100" }, () => {}, spendDeps(trace, cache));
  assert.equal(trace.submit, 1);

  // The user picks another account in MetaMask: a different signature, hence a
  // different bjj key, from here on.
  wallet.account = "0x00000000000000000000000000000000000000b2";
  wallet.sig = OTHER_SIG;

  // `after` counts only what the FLOWS do from here; the cache keeps counting its
  // derivations into `trace` (it was built with it).
  const after = newTrace();
  await assert.rejects(
    runSpend("withdraw", spendCtx(), { amount: "100" }, () => {}, spendDeps(after, cache)),
    new RegExp(ACCOUNT_MISMATCH_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.equal(trace.derive, 1, "the held key proves the mismatch — the switch costs no signature");
  assert.equal(after.head, 0);
  assert.equal(after.submit, 0);

  // The refusal dropped the hold, so the deposit re-derives — and is refused too,
  // this time on the freshly derived foreign key, before any approve tx.
  await assert.rejects(
    runDeposit(depositCtx(), { amount: "100" }, () => {}, depositDeps(after, cache)),
    new RegExp(ACCOUNT_MISMATCH_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.equal(trace.derive, 2, "with nothing held, the foreign key itself is the evidence");
  assert.equal(after.approve, 0, "and costs no approve tx either");
});

test("signing out re-locks: the next action derives again", async () => {
  const trace = newTrace();
  const cache = testCache(trace, sessionWallet());
  await runSpend("withdraw", spendCtx(), { amount: "100" }, () => {}, spendDeps(trace, cache));
  assert.equal(trace.derive, 1);

  cache.lock(); // what App.endSession does on Disconnect

  const stages: string[] = [];
  await runSpend("withdraw", spendCtx(), { amount: "100" }, (s) => stages.push(s), spendDeps(trace, cache));
  assert.equal(trace.derive, 2, "a signed-out wallet holds nothing");
  assert.equal(stages[0], "unlock");
});
