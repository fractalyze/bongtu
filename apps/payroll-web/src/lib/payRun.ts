// ONE click -> the whole pay run (SPEC §7 employer-mode, U-P3). The chain
// decomposition is split exactly on the package boundary:
//
//   @bongtu/client owns "merge until ONE note covers the total" — runMergeChain
//   (spendFlow.ts) plans and runs the transfer10x2 self-merges, wallet-style,
//   and hands back the single funding note;
//
//   THIS app owns the terminal leg — the 1-in/256-out disburse: fetch the
//   funding note's signed membership, assemble with lib/disburse.ts (its
//   CSPRNG-randomized pads/salts/shuffle intact — recipient-count privacy),
//   prove on the service, submit disburseWithCiphertexts.
//
// Every proof goes through the injected `prove` (the prover-service adapter —
// payroll never proves in the browser); every stage reports through the same
// OnSpendStage the merge legs use, numbered over merges + 1, so the Console's
// progress rail renders the whole run as one chain.

import type { MembershipWitness } from "@bongtu/client/spend";
import {
  runMergeChain,
  type OnSpendStage,
  type SpendContext,
  type SpendIo,
  type SpendOutcome,
} from "@bongtu/client/spendFlow";
import { assertPoolKemEpoch, ensureChain } from "@bongtu/client/connection";
import { getHead, getSignedPath } from "@bongtu/client/indexerClient";
import { DEFAULTS } from "../config.js";
import { buildDisburseRequest, freshDisburseKem, type RecipientRow } from "./disburse.js";
import { submitDisburse } from "./chain.js";
import { payrollErrorMessage } from "./errors.js";
import type { proveViaService } from "./proverClient.js";

/** B disburse outputs, ONE of them reserved for the employer's change note — so a
 *  single run pays at most B-1 people. The worksheet caps its rows at the same
 *  number; this is the engine-side belt, checked before anything is signed. */
export const MAX_RECIPIENTS = DEFAULTS.batchSize - 1;

/**
 * What the console says when the TERMINAL disburse fails after merge legs have
 * already landed. @bongtu/client owns the English original (CHAIN_FAILURE_REASSURANCE,
 * which the wallet renders) — payroll speaks Korean to its operator, so the wrapper is
 * translated at this boundary rather than changed in the shared package.
 *
 * The money is the whole point: several transactions were signed and none of them
 * paid anybody, so "실패했습니다" alone reads like lost payroll.
 */
export const PAY_RUN_FAILURE_REASSURANCE =
  "자금은 안전합니다. 아무에게도 지급되지 않았고, 이미 합쳐진 노트는 그대로 남아 있어 다시 시도하면 더 짧은 과정으로 끝납니다.";

export interface PayRunResult {
  /** the terminal disburse transaction — what the done screen links. */
  txHash: string;
  explorerUrl: string;
  /** the merge transactions that ran first (empty for a single-note balance). */
  mergeTxs: SpendOutcome[];
  recipientCount: number;
}

/** The I/O edges a run touches beyond the merge chain's own (all real by
 *  default; injectable so the terminal-leg order gates headlessly if needed). */
export interface PayRunDeps {
  /** the prover-service adapter (proveViaService with the base URL applied). */
  prove: Parameters<typeof runMergeChain>[3]["prove"];
  keyCache: SpendIo["keyCache"];
  runMergeChain?: typeof runMergeChain;
  ensureChain?: typeof ensureChain;
  assertPoolKemEpoch?: typeof assertPoolKemEpoch;
  getHead?: typeof getHead;
  getSignedPath?: typeof getSignedPath;
  submitDisburse?: typeof submitDisburse;
  poll?: SpendIo["poll"];
}

/** What proveViaService looks like once the base URL is applied — the shape both
 *  the merge legs and the terminal disburse prove through. */
export type ProveFn = (request: Parameters<typeof proveViaService>[1]) => ReturnType<typeof proveViaService>;

/**
 * Run the whole pay: merges (client machinery) then the disburse (this app).
 * `recipients` are worksheet-validated rows — canonical hex addresses, raw wei
 * amounts. Throws the engine's own readable errors (insufficient balance, a
 * rejected wallet popup, a stale root) for the Console to show verbatim.
 */
export async function runPayRun(
  ctx: SpendContext,
  recipients: RecipientRow[],
  onStage: OnSpendStage,
  deps: PayRunDeps,
): Promise<PayRunResult> {
  // The batch bounds, checked before ANY leg runs: an empty sheet has nothing to
  // sign for, and a sheet past B-1 recipients cannot fit the circuit's output
  // slots — either would otherwise surface after minutes of merges and proving.
  if (recipients.length === 0) throw new Error("지급할 행이 없습니다.");
  if (recipients.length > MAX_RECIPIENTS) {
    throw new Error(`한 번에 최대 ${MAX_RECIPIENTS}명까지 지급할 수 있습니다. (지금 ${recipients.length}명)`);
  }
  const total = recipients.reduce((s, r) => s + BigInt(r.amount), 0n);
  const io = {
    runMergeChain: deps.runMergeChain ?? runMergeChain,
    ensureChain: deps.ensureChain ?? ensureChain,
    assertPoolKemEpoch: deps.assertPoolKemEpoch ?? assertPoolKemEpoch,
    getHead: deps.getHead ?? getHead,
    getSignedPath: deps.getSignedPath ?? getSignedPath,
    submitDisburse: deps.submitDisburse ?? submitDisburse,
  };

  // The merges: zero or more transfer10x2 self-sends until one note covers the
  // total, each leg guarded (chain, KEM epoch, session-account) by the engine.
  const { funding, mergeTxs } = await io.runMergeChain(ctx, total.toString(), onStage, {
    keyCache: deps.keyCache,
    prove: deps.prove,
    ...(deps.poll ? { poll: deps.poll } : {}),
  });

  // The terminal leg — same guard order as a merge leg (openSpendSession), then
  // membership -> assemble -> prove -> submit.
  const leg = { index: mergeTxs.length, count: mergeTxs.length + 1 };
  try {
    onStage(deps.keyCache.isUnlocked() ? "assemble" : "unlock", leg);
    await io.ensureChain(ctx.connection);
    await io.assertPoolKemEpoch(ctx.connection, ctx.pool);
    const identity = await deps.keyCache.unlock(ctx.connection, ctx.sessionPubkey);
    onStage("assemble", leg);

    const head = await io.getHead(ctx.indexerUrl);
    const path = await io.getSignedPath(
      ctx.indexerUrl,
      funding.leafIndex,
      identity.compressedPubkey,
      identity.keypair.formattedPrivateKey,
    );
    const membership: MembershipWitness = {
      root: head.root,
      pathElements: path.siblings,
      leafIndex: funding.leafIndex,
    };

    // Fresh ML-KEM encapsulation per batch (ct reuse collapses the PQ compartment);
    // the ecdh/nonce/salts/pad keys/shuffle are drawn inside buildDisburseRequest
    // from the CSPRNG — recipient-count privacy, never operator inputs.
    const kem = freshDisburseKem();
    const built = buildDisburseRequest(
      {
        value: funding.value,
        salt: funding.salt,
        ownerPrivateKey: identity.keypair.formattedPrivateKey.toString(),
      },
      membership,
      recipients,
      { authorityPubKey: DEFAULTS.arbiterPubKey, kemSs: kem.kemSs, kemCiphertext: kem.kemCiphertext },
    );
    // The builder folds the funding note's path itself — refuse to spend a proof
    // (and the user's wait) on a root the balance has already moved past.
    if (!built.meta.membershipOk) {
      throw new Error("잔고가 방금 바뀌었습니다. 잠시 후 다시 시도하세요.");
    }

    onStage("prove", leg);
    const calldata = await deps.prove(built.request);

    onStage("submit", leg);
    const res = await io.submitDisburse(
      ctx.connection,
      ctx.pool,
      calldata,
      built.ciphertext,
      built.kemCiphertext,
      ctx.explorer,
    );
    return { txHash: res.txHash, explorerUrl: res.explorerUrl, mergeTxs, recipientCount: recipients.length };
  } catch (e) {
    // A run with no merges fails exactly as a single transaction does — the
    // reassurance is about the legs that already landed, and would only puzzle
    // someone who signed once. (Same rule @bongtu/client applies to its chains.)
    if (mergeTxs.length === 0) throw e;
    throw new Error(`${payrollErrorMessage(e)} ${PAY_RUN_FAILURE_REASSURANCE}`);
  }
}
