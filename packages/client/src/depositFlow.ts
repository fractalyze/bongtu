// The approve+prove+submit orchestration for the public wallet's deposit/shield action
// (SPEC §7). Modeled on spendFlow.ts runSpendChain: instead of DOM status lines it reports a
// coarse stage ("approve" → "prove" → "submit") through a callback the React Deposit
// screen renders as a staged progress bar. The witness assembly (deposit.ts), in-browser
// proof (prove.ts) and wallet approve/submit (connection.ts) are the same tested pure
// libs; this file is the un-tested browser wiring.
//
// A deposit is 0-in / 2-out (mint), so there is NO note selection and NO membership fetch
// — the "approve" stage replaces the spend's "assemble": exact-V ERC-20 approve, SKIPPED
// when the current allowance already covers V (one approve tx only when needed, then the
// permissionless deposit tx).

import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { Connection } from "./connection.js";
import {
  approveToken,
  assertPoolKemEpoch,
  ensureChain,
  readTokenState,
  submitDeposit,
  walletErrorMessage,
} from "./connection.js";
import type { KeyCache } from "./keyCache.js";
import { assertDepositAffordable, buildDepositRequest, freshDepositCrypto } from "./deposit.js";
import { randField } from "./spend.js";

/** The coarse stages a deposit passes through. "unlock" is the signature that hands
 *  over the spending key and fires ONLY when the wallet is locked; "approve" is
 *  SKIPPED (no tx) when the pool allowance already covers V; "prove" is the
 *  multi-second in-browser proof. */
export type DepositStage = "unlock" | "approve" | "prove" | "submit";

export interface DepositContext {
  connection: Connection;
  /** the pool address the deposit approves and submits to (app config). */
  pool: string;
  /** the wrapped kKRW ERC-20 the pool escrows (app config). */
  token: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any kKRW is shielded. */
  sessionPubkey: string;
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
  assertPoolKemEpoch: typeof assertPoolKemEpoch;
  ensureChain: typeof ensureChain;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCache;
  /** Turn a ProvingRequest into Groth16 calldata. The APP supplies this: wallet-web
   *  injects in-browser snarkjs (prove.ts proveInBrowser with its circuit asset
   *  base URL applied); payroll-web will inject its prover-service adapter. */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  submitDeposit: typeof submitDeposit;
}

/** What every deposit must be handed: the app's lock instance and its prover. The
 *  engine-side edges (token reads, guards, submits) default to the real ones. */
export type DepositIo = Pick<RunDepositDeps, "keyCache" | "prove"> & Partial<RunDepositDeps>;

const DEFAULT_DEPS: Omit<RunDepositDeps, "keyCache" | "prove"> = {
  readTokenState,
  approveToken,
  assertPoolKemEpoch,
  ensureChain,
  submitDeposit,
};

/**
 * Approve (if needed) → assemble the deposit witness → prove in-browser → submit the
 * permissionless deposit through the connected wallet. `onStage` fires as each coarse
 * stage begins. The
 * approve stage submits an exact-V approve ONLY when the current pool allowance is below
 * V; otherwise it is a no-op tx-wise (the stage still fires so the UI shows it advancing).
 *
 * Guards run cheapest-first, all of them before the approve tx: the pool's KEM epoch
 * (a view call), the depositor's public kKRW balance (assertDepositAffordable — a
 * doomed deposit must not waste an approve tx and a multi-second proof on a
 * safeTransferFrom that would revert), then the unlock, whose session-account check
 * refuses a key that isn't this session's.
 *
 * Throws the same distinct errors the pure lib raises (non-positive amount, insufficient
 * balance) plus any wallet / RPC failure, because the UI shows the thrown message
 * verbatim rather than mapping error codes of its own.
 */
export async function runDeposit(
  ctx: DepositContext,
  args: { amount: string },
  onStage: (stage: DepositStage) => void,
  deps: DepositIo,
): Promise<DepositOutcome> {
  const io: RunDepositDeps = { ...DEFAULT_DEPS, ...deps };
  const amount = args.amount.trim();
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);

  // Announce the signature stage up front when the wallet is locked, so the progress
  // list never has to step backwards into a popup it didn't predict.
  const locked = !io.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "approve");
  // A silently-restored session may still sit on another chain — align it before
  // the token reads and every tx below (silent when the chain is already selected).
  await io.ensureChain(ctx.connection);
  // Verify the pool's arbiter KEM key hash FIRST: a pre-KEM or foreign-keyed pool
  // can never accept this build's proof, so nothing below — not the approve tx, not
  // the signature popup, not the multi-second proof — is worth spending on it.
  await io.assertPoolKemEpoch(ctx.connection, ctx.pool);
  const { balance, allowance } = await io.readTokenState(
    ctx.connection,
    ctx.token,
    ctx.connection.address,
    ctx.pool,
  );
  // Fail BEFORE the approve tx + proof if the public balance can't cover V (the pool's
  // safeTransferFrom would revert on-chain anyway).
  assertDepositAffordable(V, balance);
  // The spending key comes from the in-memory lock: one signature the first time,
  // reused after that (keyCache.ts). It resolves BEFORE the approve tx so that a
  // mid-session account switch costs the user nothing — minting into a stranger's
  // key must never be preceded by an approve the user paid gas for.
  const identity = await io.keyCache.unlock(ctx.connection, ctx.sessionPubkey);
  if (locked) onStage("approve");
  let approved = false;
  if (allowance < V) {
    await io.approveToken(ctx.connection, ctx.token, ctx.pool, V);
    approved = true;
  }

  try {
    onStage("prove");
    const crypto = freshDepositCrypto(randField);
    const built = buildDepositRequest(identity, amount, crypto);
    const calldata = await io.prove(built.request);

    onStage("submit");
    // The tx carries the SAME encapsulation the proof's kemBinding committed to
    // (crypto.kemCiphertext) — a different ct would decapsulate to mismatching
    // limbs at the arbiter and burn the envelope into an alarm.
    const res = await io.submitDeposit(ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer);
    return { txHash: res.txHash, explorerUrl: res.explorerUrl, amount, approved };
  } catch (e) {
    // The CHAIN_FAILURE_REASSURANCE pattern generalized (error-surface standard):
    // once the approve tx has landed, a later failure must say where the money
    // stands — an approval went through but nothing moved, and it is reused on
    // retry. A failure with no approve landed stays a plain single-transaction
    // failure (the reassurance would only confuse — nothing partial can exist).
    if (!approved) throw e;
    throw new Error(`${walletErrorMessage(e)} ${DEPOSIT_FAILURE_REASSURANCE}`);
  }
}

/** What a deposit says when it fails AFTER its approve tx landed. Same money-state
 *  rule as spendFlow's CHAIN_FAILURE_REASSURANCE: name what stands (the approval)
 *  and what didn't move (every token). */
export const DEPOSIT_FAILURE_REASSURANCE =
  "No kKRW left your account. The approval stays in place and is reused when you retry.";
