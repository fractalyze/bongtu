// The shared prove+submit orchestration for the public wallet's two spend actions
// (SPEC §7). Lifted VERBATIM from the old main.ts `runSpend` / `selectSpendInputs` —
// only the presentation changed: instead of writing DOM status lines it reports a
// coarse stage ("assemble" → "prove" → "submit") through a callback the React
// Send/Withdraw screens render as a staged progress bar. The witness assembly,
// membership fold, in-browser proof and wallet submit stayed in the same tested pure
// libs (spend.ts / prove.ts / metamask.ts); this file is the browser wiring, with its
// I/O behind an injectable seam so the ORDER of its guards — in particular that the
// session-account check precedes every read, proof and submit — gates headlessly
// (test/accountBinding.test.ts).

import { DEFAULTS } from "../config.js";
import type { Connection } from "./metamask.js";
import { assertPoolKemEpoch, ensureChain, submitTransfer, submitWithdraw } from "./metamask.js";
import { keyCache, type KeyCache } from "./keyCache.js";
import { getHead, getPath, type OwnerNote } from "./indexerClient.js";
import {
  buildTransferRequest,
  buildWithdrawRequest,
  selectInputNotes,
  freshSpendCrypto,
  type WalletInputNote,
  type MembershipWitness,
} from "./spend.js";
import { proveInBrowser } from "./prove.js";

/** The coarse stages a spend passes through (no witness sub-stage — witness is
 *  ~150 ms and invisible; the multi-second cost is the proof). "unlock" is the
 *  signature that hands over the spending key, and fires ONLY when the wallet is
 *  locked — an unlocked wallet starts at "assemble". */
export type SpendStage = "unlock" | "assemble" | "prove" | "submit";

export interface SpendContext {
  connection: Connection;
  indexerUrl: string;
  notes: OwnerNote[];
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any of these notes may be spent. */
  sessionPubkey: string;
}

export interface SpendOutcome {
  txHash: string;
  explorerUrl: string;
}

// Fresh per-tx field randomness (browser only). A shared ephemeral ECDH key + nonce
// across outputs of ONE tx is fine; reuse ACROSS txs is a two-time pad, so we draw
// fresh values every spend. (Was `randField` in main.ts.)
export function randField(): string {
  const b = new Uint8Array(31); // < 2^248, safely under the field prime
  crypto.getRandomValues(b);
  let x = 0n;
  for (const byte of b) x = (x << 8n) | BigInt(byte);
  return (x === 0n ? 1n : x).toString();
}

/** The network/proving I/O runSpend performs, injectable so the pure orchestration
 *  (guard order, stage order) is unit-testable with fakes — the same seam
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
  submitWithdraw: typeof submitWithdraw;
}
const DEFAULT_DEPS: RunSpendDeps = {
  ensureChain,
  assertPoolKemEpoch,
  keyCache,
  getHead,
  getPath,
  proveInBrowser,
  submitTransfer,
  submitWithdraw,
};

// Amount-aware note selection is PURE + unit-tested (spend.ts selectInputNotes); this
// wiring only fetches the live membership witnesses for the selected leaves.
async function selectSpendInputs(
  io: RunSpendDeps,
  indexerUrl: string,
  notes: OwnerNote[],
  amount: string,
): Promise<{ inputs: WalletInputNote[]; memberships: MembershipWitness[] }> {
  const inputs = selectInputNotes(notes, amount);
  const head = await io.getHead(indexerUrl);
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    const p = await io.getPath(indexerUrl, n.leafIndex); // 422 for a within-batch leaf in public mode
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return { inputs, memberships };
}

/**
 * Select notes → assemble the witness → prove in-browser → submit through the
 * connected wallet, for a transfer (needs `to`) or a withdraw (no recipient).
 * `onStage` fires as each coarse stage begins. Throws the same distinct errors the
 * pure libs raise (insufficient balance, needs-more-than-2-notes, membership-stale,
 * …) for the UI to show.
 */
export async function runSpend(
  kind: "transfer" | "withdraw",
  ctx: SpendContext,
  args: { to?: string; amount: string },
  onStage: (stage: SpendStage) => void,
  deps: Partial<RunSpendDeps> = {},
): Promise<SpendOutcome> {
  const io = { ...DEFAULT_DEPS, ...deps };
  // Announce the signature stage up front when the wallet is locked, so the progress
  // list never has to step backwards into a popup it didn't predict.
  const locked = !io.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "assemble");
  // A silently-restored session may still sit on another chain — align it before
  // any chain read/submit (silent when GIWA is already selected).
  await io.ensureChain(ctx.connection);
  // Verify the pool's arbiter KEM key hash BEFORE encapsulating (design doc
  // §4/§5) — refuse to draw KEM material against a pool the chain does not
  // vouch for (pre-KEM V1, or a rotated/foreign key).
  await io.assertPoolKemEpoch(ctx.connection, DEFAULTS.pool);
  // The spending key comes from the in-memory lock: one signature the first time,
  // reused after that, and refused outright when the account selected in the
  // connected wallet is no longer this session's (keyCache.ts). Nothing is read,
  // proven or submitted before it resolves; it leaves via built.request only as
  // witness input to the in-browser prover.
  const identity = await io.keyCache.unlock(ctx.connection, ctx.sessionPubkey);
  if (locked) onStage("assemble");
  const { inputs, memberships } = await selectSpendInputs(io, ctx.indexerUrl, ctx.notes, args.amount);
  const crypto = freshSpendCrypto(randField);
  const built =
    kind === "transfer"
      ? buildTransferRequest(identity, inputs, memberships, args.to ?? "", args.amount, crypto)
      : buildWithdrawRequest(identity, inputs, memberships, args.amount, crypto);
  if (!built.meta.membershipOk) {
    throw new Error("Your balance just changed — go back and try again.");
  }

  onStage("prove");
  const calldata = await io.proveInBrowser(built.request, DEFAULTS.circuitBaseUrl);

  onStage("submit");
  // The tx carries the SAME encapsulation the proof's kemBinding committed to
  // (crypto.kemCiphertext) — a different ct would decapsulate to mismatching
  // limbs at the arbiter and burn the envelope into an alarm.
  const res =
    kind === "transfer"
      ? await io.submitTransfer(ctx.connection, DEFAULTS.pool, calldata, crypto.kemCiphertext, DEFAULTS.explorer)
      : await io.submitWithdraw(ctx.connection, DEFAULTS.pool, calldata, crypto.kemCiphertext, DEFAULTS.explorer);
  return { txHash: res.txHash, explorerUrl: res.explorerUrl };
}
