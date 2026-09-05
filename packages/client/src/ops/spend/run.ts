// The shared prove+submit orchestration for the public wallet's two spend actions
// (SPEC §7). The witness assembly, membership fold, in-browser proof and wallet submit
// stay in the same tested pure libs (spend.ts / prove.ts / connection.ts); this file is
// the browser wiring, with its I/O behind an injectable seam so the ORDER of its
// guards — in particular that the session-account check precedes every read, proof and
// submit — gates headlessly (test/accountBinding.test.ts).
//
// A SPEND IS A CHAIN, not a transaction. A spending circuit takes a fixed number of
// input notes, so a balance spread across more notes than that cannot be paid in one
// go. The wallet does not stop and send the user off to merge first: planSpendChain
// (spend.ts) plans the whole way through — however many transfer10x2 self-sends it
// takes to fold the balance down, then the payment itself — and runSpendChain below
// runs the legs back to back, one wallet approval each. A plain send is simply a chain
// of one, and runs byte-identically to what it always did. (transfer10 is deprecated,
// 2026-07-28: no leg of any chain proves or submits it anymore.)
//
// Between legs the chain WAITS. A merge leg's output note does not exist for the next
// leg until the indexer has seen the transaction: only then does the note have a leaf
// index and a membership path to prove against. That wait is a reported stage of its
// own ("waiting"), so the screen can say what it is waiting for.

import { commitment } from "@bongtu/core/note";
import type { StealthDerivation } from "@bongtu/core/stealth";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { Connection } from "@bongtu/client/connection";
import {
  assertPoolKemEpoch,
  ensureChain,
  submitTransfer,
  submitTransfer10x2,
  submitWithdraw,
  walletErrorMessage,
} from "@bongtu/client/connection";
import { submitWithdrawRelayed } from "@bongtu/client/relayer";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import { getHead, getSignedPath, type OwnerNote } from "@bongtu/core/indexerApi";
import { pollUntil, type PollForActionOptions } from "@bongtu/client/refresh";
import {
  buildTransferRequest,
  buildTransfer10x2Request,
  buildWithdrawRequest,
} from "./builders.js";
import {
  planDisburseChain,
  planSpendChain,
  pendingLegOf,
  type SpendAction,
  type SpendCrypto,
  type SpendKind,
  type SpendLeg,
  type WalletInputNote,
  type MembershipWitness,
} from "./plan.js";
import { freshSpendCrypto, randField } from "./crypto.js";
import type { WalletIdentity } from "@bongtu/client/derive";

/** The coarse stages a spend leg passes through (no witness sub-stage — witness is
 *  ~150 ms and invisible; the multi-second cost is the proof). "unlock" is the
 *  signature that hands over the spending key, and fires ONLY when the wallet is
 *  locked — an unlocked wallet starts at "assemble". "waiting" is the pause after a
 *  merge leg, while the indexer catches up enough for the next leg to be built. */
export type SpendStage = "unlock" | "assemble" | "prove" | "submit" | "waiting";

/** Which transaction of the chain is reporting, and how many there are in total. */
export interface LegProgress {
  index: number;
  count: number;
}

/** How a run reports itself: a stage, and the leg it belongs to. */
export type OnSpendStage = (stage: SpendStage, leg: LegProgress) => void;

export interface SpendContext {
  connection: Connection;
  indexerUrl: string;
  /** the pool address every leg proves against and submits to (app config). */
  pool: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the gas-sponsoring relayer base URL (app config; apps/relayer). Set => the
   *  terminal WITHDRAW leg is submitted through it — no wallet popup, the
   *  relayer pays gas, and it cannot redirect the payout because the recipient
   *  is proof-bound (pub[26]). Absent/empty => wallet self-submit, the
   *  pre-relayer behavior. Transfer and merge legs NEVER relay: they carry no
   *  proof-bound recipient, so there is nothing a relayer could safely offer. */
  relayerUrl?: string;
  notes: OwnerNote[];
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any of these notes may be spent, and the payee
   *  of every merge leg. */
  sessionPubkey: string;
  /** Re-read the owner's notes from the indexer. A chain cannot plan its next leg
   *  from `notes` alone: the note a merge just created is not in there, and only the
   *  indexer can say which leaf it landed on. */
  reloadNotes: () => Promise<OwnerNote[]>;
}

export interface SpendOutcome {
  txHash: string;
  explorerUrl: string;
}

/** The network/proving I/O a spend performs, injectable so the pure orchestration
 *  (guard order, stage order, leg order) is unit-testable with fakes — the same seam
 *  ops/deposit.ts uses (RunDepositDeps). Defaults are the real edges. */
export interface RunSpendDeps {
  ensureChain: typeof ensureChain;
  assertPoolKemEpoch: typeof assertPoolKemEpoch;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  getHead: typeof getHead;
  getSignedPath: typeof getSignedPath;
  /** Turn a ProvingRequest into Groth16 calldata. The APP supplies this: wallet-web
   *  injects in-browser snarkjs (prove.ts proveInBrowser with its circuit asset
   *  base URL applied); payroll-web will inject its prover-service adapter. */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  submitTransfer: typeof submitTransfer;
  submitTransfer10x2: typeof submitTransfer10x2;
  submitWithdraw: typeof submitWithdraw;
  /** reached only when ctx carries a relayerUrl, and only by the terminal
   *  withdraw leg (io/relayer.ts). */
  submitWithdrawRelayed: typeof submitWithdrawRelayed;
  /** interval/cap/sleep for the between-legs wait — the wallet's one bounded-poll
   *  policy (refresh.ts), so tests can run a chain without real seconds. */
  poll: PollForActionOptions;
}

/** What every spend must be handed: the app's lock instance and its prover. The
 *  engine-side edges (chain guard, indexer reads, submits) default to the real ones. */
export type SpendIo = Pick<RunSpendDeps, "keyCache" | "prove"> & Partial<RunSpendDeps>;

const DEFAULT_DEPS: Omit<RunSpendDeps, "keyCache" | "prove"> = {
  ensureChain,
  assertPoolKemEpoch,
  getHead,
  getSignedPath,
  submitTransfer,
  submitTransfer10x2,
  submitWithdraw,
  submitWithdrawRelayed,
  poll: {},
};

// Circuit choice and note selection are PURE + unit-tested (spend.ts
// planSpendChain); this wiring only fetches the live membership witnesses for the
// selected leaves — freshly per leg, because each leg moves the root. Every fetch
// is SIGNED with the (already-unlocked) spending key: a disbursed note lives
// inside a batch, and the arbiter indexer only opens a batch slot to the owner
// who proves it (routes/path.ts); for single-append leaves the auth is ignored.
async function fetchMemberships(
  io: RunSpendDeps,
  indexerUrl: string,
  identity: WalletIdentity,
  inputs: WalletInputNote[],
): Promise<MembershipWitness[]> {
  const head = await io.getHead(indexerUrl);
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    // 422 for a within-batch leaf in public mode
    const p = await io.getSignedPath(indexerUrl, n.leafIndex, identity.compressedPubkey, identity.keypair.formattedPrivateKey);
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return memberships;
}

// Each circuit's builder gets exactly the witness its `main` takes; withdraw's
// payee is an L1 address (the proof-bound payout target), and transfer10x2
// serves both the 3–10-note payment and the merge legs.
function buildRequest(
  action: SpendAction,
  identity: WalletIdentity,
  memberships: MembershipWitness[],
  crypto: SpendCrypto,
  withdrawRecipient: string,
) {
  // (withdrawRecipient is ignored by the transfer builders.)
  const { circuit, inputs, to, amount } = action;
  if (circuit === "withdraw") return buildWithdrawRequest(identity, inputs, memberships, amount, crypto, withdrawRecipient);
  if (circuit === "transfer10x2") {
    return buildTransfer10x2Request(identity, inputs, memberships, to, amount, crypto);
  }
  return buildTransferRequest(identity, inputs, memberships, to, amount, crypto);
}

/**
 * The guards that must pass before ANY read, proof or submit, in this order: align
 * the chain, refuse a pool whose arbiter KEM key the chain does not vouch for, then
 * take the spending key from the wallet's lock — one signature the first time, reused
 * after that, and refused outright when the account selected in the connected wallet
 * is no longer this session's (keyCache.ts). Re-run per LEG, so an account switched
 * midway through a chain blocks the remaining transactions rather than signing them
 * with someone else's key.
 *
 * The "unlock" stage is announced up front when the wallet is locked, so the progress
 * list never has to step backwards into a popup it didn't predict.
 */
async function openSpendSession(
  io: RunSpendDeps,
  ctx: SpendContext,
  onStage: OnSpendStage,
  leg: LegProgress,
): Promise<WalletIdentity> {
  const locked = !io.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "assemble", leg);
  await io.ensureChain(ctx.connection);
  await io.assertPoolKemEpoch(ctx.connection, ctx.pool);
  // Nothing is read, proven or submitted before this resolves; the key leaves via
  // built.request only as witness input to the in-browser prover.
  const identity = await io.keyCache.unlock(ctx.connection, ctx.sessionPubkey);
  if (locked) onStage("assemble", leg);
  return identity;
}

/** One transaction: membership → witness → in-browser proof → wallet submit. The
 *  per-tx salt comes back with it, because a merge leg's output note is identified
 *  by the salt this run drew for it. */
async function runLeg(
  io: RunSpendDeps,
  ctx: SpendContext,
  identity: WalletIdentity,
  action: SpendAction,
  onStage: OnSpendStage,
  leg: LegProgress,
  stealth?: StealthDerivation,
  withdrawTo?: string,
): Promise<{ outcome: SpendOutcome; payeeSalt: string }> {
  const memberships = await fetchMemberships(io, ctx.indexerUrl, identity, action.inputs);
  const crypto = freshSpendCrypto(randField);
  // Withdraw pays the CONNECTED account by default — byte-for-byte the old
  // money movement, now proof-bound instead of msg.sender-implied. A user-typed
  // destination (withdrawTo) substitutes theirs through the SAME proof-bound
  // param; a stealth run substitutes its freshly derived one-time address.
  const built = buildRequest(
    action, identity, memberships, crypto,
    stealth?.address ?? withdrawTo ?? ctx.connection.address,
  );
  if (!built.meta.membershipOk) {
    throw new Error("Your balance just changed. Go back and try again.");
  }

  onStage("prove", leg);
  const calldata = await io.prove(built.request);

  onStage("submit", leg);
  // The tx carries the SAME encapsulation the proof's kemBinding committed to
  // (crypto.kemCiphertext) — a different ct would decapsulate to mismatching
  // limbs at the arbiter and burn the envelope into an alarm.
  // Withdraw alone may go through the gas-sponsoring relayer (ctx.relayerUrl):
  // its payout target is proof-bound (pub[26]), so a third-party submitter can
  // pay the gas without being able to redirect it. A configured-but-failing
  // relayer THROWS here rather than falling back to the wallet — silently
  // paying gas from the user's own account is the promise the relayer breaks
  // (io/relayer.ts owns that WHY). Merge legs are transfer10x2 and take the
  // non-withdraw branch, so they can never relay by construction.
  const res =
    action.circuit === "withdraw"
      ? ctx.relayerUrl
        ? await io.submitWithdrawRelayed(
            ctx.relayerUrl, calldata, crypto.kemCiphertext, ctx.explorer, stealth,
          )
        : await io.submitWithdraw(
            // The derivation travels WHOLE: connection.ts maps its announcement
            // half to calldata, and splitting it here is exactly the seam where
            // the pays-what-it-announces invariant could silently break.
            ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer, stealth,
          )
      : await (action.circuit === "transfer" ? io.submitTransfer : io.submitTransfer10x2)(
          ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer,
        );
  return {
    outcome: { txHash: res.txHash, explorerUrl: res.explorerUrl },
    payeeSalt: crypto.payeeSalt ?? "",
  };
}

/** Resolve one planned leg into the action that proves it. A merge pays the wallet
 *  itself the whole fold; a terminal leg pays whoever the user typed. Inputs the plan
 *  left pending are the notes earlier merges have since created. */
function legAction(
  step: SpendLeg,
  ctx: SpendContext,
  args: { to?: string; amount: string },
  merged: (WalletInputNote | undefined)[],
): SpendAction {
  const inputs = step.inputs.map((n) => {
    const from = pendingLegOf(n.leafIndex);
    if (from === null) return n;
    const real = merged[from];
    if (!real) throw new Error(`merge leg ${from + 1} has not produced its note yet`);
    return real;
  });
  if (step.leg === "merge") {
    return { circuit: "transfer10x2", inputs, to: ctx.sessionPubkey, amount: step.mergedValue };
  }
  return { circuit: step.leg, inputs, to: args.to ?? "", amount: args.amount };
}

/** What a merge leg's note will look like once the indexer has it: output 0 of the
 *  transfer10x2, worth the whole fold, owned by the wallet, on this run's payee salt
 *  (output 1 is the zero-value change note). */
function mergedNoteCommitment(
  identity: WalletIdentity,
  mergedValue: string,
  payeeSalt: string,
): string {
  return commitment(BigInt(mergedValue), BigInt(payeeSalt), identity.keypair.publicKey).toString();
}

export const MERGE_NOT_INDEXED_MESSAGE =
  "The network has not recorded your combined note yet. Try again in a moment.";

/** Wait for the indexer to record the note a merge leg created, and answer with it —
 *  its leaf index is what the next leg proves membership against. */
async function awaitMergedNote(
  io: RunSpendDeps,
  ctx: SpendContext,
  identity: WalletIdentity,
  mergedValue: string,
  payeeSalt: string,
): Promise<WalletInputNote> {
  const wanted = mergedNoteCommitment(identity, mergedValue, payeeSalt);
  const seen = (notes: OwnerNote[]): OwnerNote | undefined =>
    notes.find((n) => n.commitment === wanted && !n.spent);
  const { last } = await pollUntil(ctx.reloadNotes, (ns) => seen(ns) !== undefined, io.poll);
  const note = last ? seen(last) : undefined;
  if (!note) throw new Error(MERGE_NOT_INDEXED_MESSAGE);
  return { value: mergedValue, salt: payeeSalt, leafIndex: note.leafIndex };
}

/** What a chain says when a leg fails partway through. The money is the point: no
 *  payment left the wallet, and the merges that DID land are not undone — retrying
 *  simply plans a shorter chain over the notes that are now fewer. */
export const CHAIN_FAILURE_REASSURANCE =
  "Nothing was sent. Your balance is unchanged, and already-combined pieces stay combined.";

/**
 * Plan the spend as a chain of transactions and run it: for each leg, fetch fresh
 * membership → assemble the witness → prove in-browser → submit through the connected
 * wallet, and after a merge leg, wait for the indexer to record the note it created.
 * `onStage` fires as each stage of each leg begins, carrying which leg it is, so the
 * screen can show "Combining (1 of 2)" and then the payment.
 *
 * Throws the same distinct errors the pure libs raise (insufficient balance,
 * membership-stale, the wallet's own rejection) for the UI to show. A chain that
 * fails partway also carries the reassurance above, because "your send failed" reads
 * very differently when two transactions already went through.
 */
export async function runSpendChain(
  kind: SpendKind,
  ctx: SpendContext,
  // `stealth` is the core derivation from prepareStealthDestination
  // (stealthKeys.ts), consumed only by the terminal withdraw leg. `withdrawTo`
  // is a user-specified L1 payout address for a plain withdraw (undefined pays
  // the connected account): it rides the same proof-bound recipient param, and
  // because no derivation reaches submitWithdraw, the announcement fields stay
  // the plain-withdraw sentinel (core ZERO_EPHEMERAL) exactly as the default.
  args: { to?: string; amount: string; stealth?: StealthDerivation; withdrawTo?: string },
  onStage: OnSpendStage,
  deps: SpendIo,
): Promise<SpendOutcome> {
  const io: RunSpendDeps = { ...DEFAULT_DEPS, ...deps };
  // Planning is pure and touches nothing, so it happens FIRST: a wallet that cannot
  // afford the amount learns that before it is asked for a signature.
  const plan = planSpendChain(kind, ctx.notes, args.amount);
  const count = plan.length;
  const merged: (WalletInputNote | undefined)[] = [];
  const outcomes: SpendOutcome[] = [];

  for (const index of Array(count).keys()) {
    const leg: LegProgress = { index, count };
    const step = plan[index];
    try {
      const identity = await openSpendSession(io, ctx, onStage, leg);
      // Only the terminal leg is the withdraw the stealth destination is for;
      // a merge pays the wallet itself and must never consume it.
      const run = await runLeg(
        io, ctx, identity, legAction(step, ctx, args, merged), onStage, leg,
        step.leg === "merge" ? undefined : args.stealth,
        step.leg === "merge" ? undefined : args.withdrawTo,
      );
      outcomes.push(run.outcome);
      if (step.leg === "merge") {
        onStage("waiting", leg);
        merged[index] = await awaitMergedNote(io, ctx, identity, step.mergedValue, run.payeeSalt);
      }
    } catch (e) {
      // A one-transaction spend fails exactly as it always did — the reassurance is
      // about the legs a chain may already have landed, and would only confuse here.
      if (count === 1) throw e;
      throw new Error(`${walletErrorMessage(e)} ${CHAIN_FAILURE_REASSURANCE}`);
    }
  }
  // The terminal leg is the transaction the user asked for: it is what the success
  // screen links and what the post-action refresh polls for.
  return outcomes[outcomes.length - 1] as SpendOutcome;
}

/** What runMergeChain hands back: the single note that now covers the amount —
 *  ready to be the terminal transaction's one input — and the merge transactions
 *  that made it (empty when the balance already held such a note). */
export interface MergeChainResult {
  funding: WalletInputNote;
  mergeTxs: SpendOutcome[];
}

/**
 * Run the merges that put a 1-input terminal transaction within reach: plan with
 * planDisburseChain (spend.ts), run each merge leg exactly like runSpendChain runs
 * its own — session guards per leg, fresh membership, transfer10x2 self-send, then
 * the "waiting" pause until the indexer has the merged note — and hand back the
 * funding note. The terminal leg (payroll's 1-in/256-out disburse) is the CALLER's
 * transaction: this package owns "merge until one note covers the total", the app
 * owns what that note then pays for.
 *
 * `onStage` legs are numbered over merges + 1 — the +1 being the terminal
 * transaction the caller runs next — so one progress rail can show the whole run
 * ("combining 1 of 3 … paying 3 of 3") without the caller re-deriving the count.
 *
 * Throws `insufficient` (planning, before anything is signed) and, once any merge
 * has landed, wraps a later failure with CHAIN_FAILURE_REASSURANCE — the merges
 * that went through are real notes, and a retry plans a shorter chain over them.
 */
export async function runMergeChain(
  ctx: SpendContext,
  amount: string,
  onStage: OnSpendStage,
  deps: SpendIo,
): Promise<MergeChainResult> {
  const io: RunSpendDeps = { ...DEFAULT_DEPS, ...deps };
  const plan = planDisburseChain(ctx.notes, amount);
  const count = plan.merges.length + 1; // + the caller's terminal transaction
  const merged: (WalletInputNote | undefined)[] = [];
  const mergeTxs: SpendOutcome[] = [];

  for (const index of Array(plan.merges.length).keys()) {
    const leg: LegProgress = { index, count };
    const step = plan.merges[index];
    try {
      const identity = await openSpendSession(io, ctx, onStage, leg);
      const action = legAction(step, ctx, { amount }, merged);
      const run = await runLeg(io, ctx, identity, action, onStage, leg);
      mergeTxs.push(run.outcome);
      onStage("waiting", leg);
      merged[index] = await awaitMergedNote(io, ctx, identity, step.mergedValue, run.payeeSalt);
    } catch (e) {
      // Same money-state rule as runSpendChain: nothing terminal was sent, and
      // the merges that DID land stay merged.
      throw new Error(`${walletErrorMessage(e)} ${CHAIN_FAILURE_REASSURANCE}`);
    }
  }

  const from = pendingLegOf(plan.funding.leafIndex);
  if (from === null) return { funding: plan.funding, mergeTxs };
  const real = merged[from];
  if (!real) throw new Error(`merge leg ${from + 1} has not produced its note yet`);
  return { funding: real, mergeTxs };
}
