// The shared prove+submit orchestration for the public wallet's two spend actions
// (SPEC §7). The witness assembly, membership fold, in-browser proof and wallet submit
// stay in the same tested pure libs (spend.ts / prove.ts / metamask.ts); this file is
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

import { ethers } from "ethers";
import { commitment } from "@bongtu/core/note";
import { GIWA_GAS_FLOOR_GWEI, explorerTxUrl } from "@bongtu/core/network";
import type { Calldata } from "@bongtu/core/proving";
import { DEFAULTS } from "../config.js";
import type { Connection, SubmitResult } from "./metamask.js";
import {
  assertPoolKemEpoch,
  ensureChain,
  submitTransfer,
  submitWithdraw,
  walletErrorMessage,
} from "./metamask.js";
import { keyCache, type KeyCache } from "./keyCache.js";
import { getHead, getPath, type OwnerNote } from "./indexerClient.js";
import { pollUntil, type PollForActionOptions } from "./refresh.js";
import {
  buildTransferRequest,
  buildTransfer10x2Request,
  buildWithdrawRequest,
  planSpendChain,
  pendingLegOf,
  freshSpendCrypto,
  randField,
  type SpendAction,
  type SpendCrypto,
  type SpendKind,
  type SpendLeg,
  type WalletInputNote,
  type MembershipWitness,
} from "./spend.js";
import type { WalletIdentity } from "./derive.js";
import { proveInBrowser } from "./prove.js";

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

// --- the transfer10x2 submit edge -------------------------------------------------
// This belongs beside submitTransfer/submitWithdraw in metamask.ts and should move
// there in the next touch of that file (owned by a parallel change right now).
// Same contract-call shape as every other op: (a, b, c, pub, kemCiphertext) at the
// GIWA gas floor (ethers' auto-estimate once overpaid ~1500x), pub = 68 signals.

const TRANSFER10X2_FRAGMENT =
  "function transfer10x2(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[68] pub, bytes kemCiphertext)";

/** Submit a proven transfer10x2 (BongtuPool V5): what every >2-input spend and
 *  every merge leg lands on since transfer10's deprecation (2026-07-28). */
export async function submitTransfer10x2(
  connection: Connection,
  poolAddr: string,
  calldata: Calldata,
  kemCiphertext: string,
  explorerBase: string,
): Promise<SubmitResult> {
  // Pre-check the KEM ct length so the contract's WrongKemCiphertextLength revert
  // becomes a readable client error (mirrors metamask.ts assertKemCiphertext).
  if (!/^0x[0-9a-fA-F]+$/.test(kemCiphertext) || (kemCiphertext.length - 2) / 2 !== 1088) {
    throw new Error(`kemCiphertext must be 1088 bytes of 0x-hex (got ${kemCiphertext.length} chars)`);
  }
  const pool = new ethers.Contract(poolAddr, [TRANSFER10X2_FRAGMENT], connection.signer);
  const tx = await pool.transfer10x2(calldata.a, calldata.b, calldata.c, calldata.pub, kemCiphertext, {
    gasPrice: ethers.utils.parseUnits(GIWA_GAS_FLOOR_GWEI, "gwei"),
  });
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: explorerTxUrl(tx.hash, explorerBase) };
}

/** The network/proving I/O a spend performs, injectable so the pure orchestration
 *  (guard order, stage order, leg order) is unit-testable with fakes — the same seam
 *  depositFlow.ts uses (RunDepositDeps). Defaults are the real edges. */
export interface RunSpendDeps {
  ensureChain: typeof ensureChain;
  assertPoolKemEpoch: typeof assertPoolKemEpoch;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCache;
  getHead: typeof getHead;
  getPath: typeof getPath;
  proveInBrowser: typeof proveInBrowser;
  submitTransfer: typeof submitTransfer;
  submitTransfer10x2: typeof submitTransfer10x2;
  submitWithdraw: typeof submitWithdraw;
  /** interval/cap/sleep for the between-legs wait — the wallet's one bounded-poll
   *  policy (refresh.ts), so tests can run a chain without real seconds. */
  poll: PollForActionOptions;
}
const DEFAULT_DEPS: RunSpendDeps = {
  ensureChain,
  assertPoolKemEpoch,
  keyCache,
  getHead,
  getPath,
  proveInBrowser,
  submitTransfer,
  submitTransfer10x2,
  submitWithdraw,
  poll: {},
};

// Circuit choice and note selection are PURE + unit-tested (spend.ts
// planSpendChain); this wiring only fetches the live membership witnesses for the
// selected leaves — freshly per leg, because each leg moves the root.
async function fetchMemberships(
  io: RunSpendDeps,
  indexerUrl: string,
  inputs: WalletInputNote[],
): Promise<MembershipWitness[]> {
  const head = await io.getHead(indexerUrl);
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    const p = await io.getPath(indexerUrl, n.leafIndex); // 422 for a within-batch leaf in public mode
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return memberships;
}

// Each circuit's builder gets exactly the witness its `main` takes; withdraw has no
// payee, and transfer10x2 serves both the 3–10-note payment and the merge legs.
function buildRequest(
  action: SpendAction,
  identity: WalletIdentity,
  memberships: MembershipWitness[],
  crypto: SpendCrypto,
) {
  const { circuit, inputs, to, amount } = action;
  if (circuit === "withdraw") return buildWithdrawRequest(identity, inputs, memberships, amount, crypto);
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
  await io.assertPoolKemEpoch(ctx.connection, DEFAULTS.pool);
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
): Promise<{ outcome: SpendOutcome; payeeSalt: string }> {
  const memberships = await fetchMemberships(io, ctx.indexerUrl, action.inputs);
  const crypto = freshSpendCrypto(randField);
  const built = buildRequest(action, identity, memberships, crypto);
  if (!built.meta.membershipOk) {
    throw new Error("Your balance just changed. Go back and try again.");
  }

  onStage("prove", leg);
  const calldata = await io.proveInBrowser(built.request, DEFAULTS.circuitBaseUrl);

  onStage("submit", leg);
  // The tx carries the SAME encapsulation the proof's kemBinding committed to
  // (crypto.kemCiphertext) — a different ct would decapsulate to mismatching
  // limbs at the arbiter and burn the envelope into an alarm.
  const submitFor = {
    transfer: io.submitTransfer,
    transfer10x2: io.submitTransfer10x2,
    withdraw: io.submitWithdraw,
  }[action.circuit];
  const res = await submitFor(
    ctx.connection,
    DEFAULTS.pool,
    calldata,
    crypto.kemCiphertext,
    DEFAULTS.explorer,
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
  args: { to?: string; amount: string },
  onStage: OnSpendStage,
  deps: Partial<RunSpendDeps> = {},
): Promise<SpendOutcome> {
  const io = { ...DEFAULT_DEPS, ...deps };
  // Planning is pure and touches nothing, so it happens FIRST: a wallet that cannot
  // afford the amount learns that before it is asked for a signature.
  const plan = planSpendChain(kind, ctx.notes, args.amount);
  const count = plan.length;
  const merged: (WalletInputNote | undefined)[] = [];
  let last: SpendOutcome | null = null;

  for (let index = 0; index < count; index++) {
    const leg: LegProgress = { index, count };
    const step = plan[index];
    try {
      const identity = await openSpendSession(io, ctx, onStage, leg);
      const run = await runLeg(io, ctx, identity, legAction(step, ctx, args, merged), onStage, leg);
      last = run.outcome;
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
  return last as SpendOutcome;
}
