// The shared prove+submit orchestration for the public wallet's two spend actions
// (SPEC §7). Lifted VERBATIM from the old main.ts `runSpend` / `selectSpendInputs` —
// only the presentation changed: instead of writing DOM status lines it reports a
// coarse stage ("assemble" → "prove" → "submit") through a callback the React
// Send/Withdraw screens render as a staged progress bar. The witness assembly,
// membership fold, in-browser proof and MetaMask submit are the same tested pure
// libs (spend.ts / prove.ts / metamask.ts); this file is the un-tested browser wiring.

import { DEFAULTS } from "../config.js";
import type { WalletIdentity } from "./derive.js";
import type { Connection } from "./metamask.js";
import { submitTransfer, submitWithdraw } from "./metamask.js";
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

/** The three coarse stages a spend passes through (no witness sub-stage — witness
 *  is ~150 ms and invisible; the multi-second cost is the proof). */
export type SpendStage = "assemble" | "prove" | "submit";

export interface SpendContext {
  identity: WalletIdentity;
  connection: Connection;
  indexerUrl: string;
  notes: OwnerNote[];
}

export interface SpendOutcome {
  txHash: string;
  explorerUrl: string;
  /** the change note value the wallet keeps (from the assembled witness meta). */
  changeValue: string;
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

// Amount-aware note selection is PURE + unit-tested (spend.ts selectInputNotes); this
// wiring only fetches the live membership witnesses for the selected leaves.
async function selectSpendInputs(
  indexerUrl: string,
  notes: OwnerNote[],
  amount: string,
): Promise<{ inputs: WalletInputNote[]; memberships: MembershipWitness[] }> {
  const inputs = selectInputNotes(notes, amount);
  const head = await getHead(indexerUrl);
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    const p = await getPath(indexerUrl, n.leafIndex); // 422 for a within-batch leaf in public mode
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return { inputs, memberships };
}

/**
 * Select notes → assemble the witness → prove in-browser → submit via MetaMask, for a
 * transfer (needs `to`) or a withdraw (no recipient). `onStage` fires as each coarse
 * stage begins. Throws the same distinct errors the pure libs raise (insufficient
 * balance, needs-more-than-2-notes, self-pay, membership-stale, …) for the UI to show.
 */
export async function runSpend(
  kind: "transfer" | "withdraw",
  ctx: SpendContext,
  args: { to?: string; amount: string },
  onStage: (stage: SpendStage) => void,
): Promise<SpendOutcome> {
  onStage("assemble");
  const { inputs, memberships } = await selectSpendInputs(ctx.indexerUrl, ctx.notes, args.amount);
  const crypto = freshSpendCrypto(randField);
  const built =
    kind === "transfer"
      ? buildTransferRequest(ctx.identity, inputs, memberships, args.to ?? "", args.amount, crypto)
      : buildWithdrawRequest(ctx.identity, inputs, memberships, args.amount, crypto);
  if (!built.meta.membershipOk) {
    throw new Error("membership witness does not fold to the live root — reload balance and retry");
  }

  onStage("prove");
  const calldata = await proveInBrowser(built.request, DEFAULTS.circuitBaseUrl);

  onStage("submit");
  const res =
    kind === "transfer"
      ? await submitTransfer(ctx.connection, DEFAULTS.pool, calldata, DEFAULTS.explorer)
      : await submitWithdraw(ctx.connection, DEFAULTS.pool, calldata, DEFAULTS.explorer);
  return { txHash: res.txHash, explorerUrl: res.explorerUrl, changeValue: built.meta.changeValue };
}
