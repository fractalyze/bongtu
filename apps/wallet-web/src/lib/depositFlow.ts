// The approve+prove+submit orchestration for the public wallet's deposit/shield action
// (SPEC §7). Modeled on spendFlow.ts runSpend: instead of DOM status lines it reports a
// coarse stage ("approve" → "prove" → "submit") through a callback the React Deposit
// screen renders as a staged progress bar. The witness assembly (deposit.ts), in-browser
// proof (prove.ts) and MetaMask approve/submit (metamask.ts) are the same tested pure
// libs; this file is the un-tested browser wiring.
//
// A deposit is 0-in / 2-out (mint), so there is NO note selection and NO membership fetch
// — the "approve" stage replaces the spend's "assemble": exact-V ERC-20 approve, SKIPPED
// when the current allowance already covers V (one approve tx only when needed, then the
// permissionless deposit tx).

import { DEFAULTS } from "../config.js";
import type { WalletIdentity } from "./derive.js";
import type { Connection } from "./metamask.js";
import { approveToken, readTokenState, submitDeposit } from "./metamask.js";
import { assertDepositAffordable, buildDepositRequest, freshDepositCrypto } from "./deposit.js";
import { proveInBrowser } from "./prove.js";
import { randField } from "./spendFlow.js";

/** The three coarse stages a deposit passes through. "approve" is SKIPPED (no tx) when
 *  the pool allowance already covers V; "prove" is the multi-second in-browser proof. */
export type DepositStage = "approve" | "prove" | "submit";

export interface DepositContext {
  identity: WalletIdentity;
  connection: Connection;
}

export interface DepositOutcome {
  txHash: string;
  explorerUrl: string;
  /** the shielded value V (raw kKRW units). */
  amount: string;
  /** whether an ERC-20 approve tx was sent (false when the allowance already covered V). */
  approved: boolean;
}

/** The network/proving I/O runDeposit performs, injectable so the pure orchestration
 *  (guards, stage order, skip-approve decision) is unit-testable with fakes — the same
 *  seam assets.ts uses (PrefetchDeps). Defaults are the real MetaMask/snarkjs edges. */
export interface RunDepositDeps {
  readTokenState: typeof readTokenState;
  approveToken: typeof approveToken;
  proveInBrowser: typeof proveInBrowser;
  submitDeposit: typeof submitDeposit;
}
const DEFAULT_DEPS: RunDepositDeps = { readTokenState, approveToken, proveInBrowser, submitDeposit };

/**
 * Approve (if needed) → assemble the deposit witness → prove in-browser → submit the
 * permissionless deposit via MetaMask. `onStage` fires as each coarse stage begins. The
 * approve stage submits an exact-V approve ONLY when the current pool allowance is below
 * V; otherwise it is a no-op tx-wise (the stage still fires so the UI shows it advancing).
 *
 * Before approving it rejects a deposit that exceeds the depositor's public kKRW balance
 * (assertDepositAffordable), so a doomed deposit fails fast instead of wasting an approve
 * tx + a multi-second proof on a safeTransferFrom that would revert.
 *
 * Throws the same distinct errors the pure lib raises (non-positive amount, insufficient
 * balance) plus any MetaMask / RPC failure for the UI to show.
 */
export async function runDeposit(
  ctx: DepositContext,
  args: { amount: string },
  onStage: (stage: DepositStage) => void,
  deps: Partial<RunDepositDeps> = {},
): Promise<DepositOutcome> {
  const io = { ...DEFAULT_DEPS, ...deps };
  const amount = args.amount.trim();
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);

  onStage("approve");
  const { balance, allowance } = await io.readTokenState(
    ctx.connection,
    DEFAULTS.token,
    ctx.connection.address,
    DEFAULTS.pool,
  );
  // Fail BEFORE the approve tx + proof if the public balance can't cover V (the pool's
  // safeTransferFrom would revert on-chain anyway).
  assertDepositAffordable(V, balance);
  let approved = false;
  if (allowance < V) {
    await io.approveToken(ctx.connection, DEFAULTS.token, DEFAULTS.pool, V);
    approved = true;
  }

  onStage("prove");
  const crypto = freshDepositCrypto(randField);
  const built = buildDepositRequest(ctx.identity, amount, crypto);
  const calldata = await io.proveInBrowser(built.request, DEFAULTS.circuitBaseUrl);

  onStage("submit");
  const res = await io.submitDeposit(ctx.connection, DEFAULTS.pool, calldata, DEFAULTS.explorer);
  return { txHash: res.txHash, explorerUrl: res.explorerUrl, amount, approved };
}
