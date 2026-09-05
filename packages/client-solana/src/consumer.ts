// The consumer-family SUBMIT layer for the Solana rail — the twin of
// @bongtu/client-evm/consumer with the rail's own submit discipline: encode
// the instruction from the ONE layout table (txbuild/data.ts), derive every
// marker PDA from the calldata publics (txbuild/accounts.ts), pre-compute the
// post-op root against live TreeState (txbuild/tree.ts), set the MANDATORY
// v1 header budget at the committed-budget-plus-headroom limits
// (txbuild/budget.ts), assert the Transaction v1 size against the gate-4
// worst cases BEFORE sending (txbuild/size.ts), then sign-and-send through
// the connection and resolve only after confirmation.
//
// The submit signatures mirror the engine's consumer rail seam
// (ops/consumer/run.ts RunConsumer*Deps) exactly, so the rail-agnostic flows
// drive these unchanged. `moduleAddress` — the EVM escape hatch for
// fresh-stack gates — has no meaning here (one program, no per-op modules)
// and is ignored.
//
// Withdraw recipient (OPEN-3 truncate-253, recipient_binding.rs): the program
// injects pub[recipient] from the RECIPIENT TOKEN ACCOUNT meta as the low 253
// bits of its address, so the account must be known at submit time — but the
// engine's submit seam carries no per-call recipient slot (calldata only, and
// 253 truncated bits cannot recover the 256-bit address). Dated deviation
// (2026-09-05): the target token account is bound at io-construction time
// (SolanaConsumerConfig.withdrawTokenAccount) and belt-checked against the
// proof's own bound recipient public — a mismatch throws before any bytes are
// sent, so the binding cannot silently diverge from what the proof pays.

import {
  compileTransaction,
  createTransactionMessage,
  appendTransactionMessageInstructions,
  setTransactionMessageConfig,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Instruction,
} from "@solana/kit";
import type { Calldata } from "@bongtu/core/proving";
import { base58ToBytes } from "@bongtu/core/solana";
import { ZERO_EPHEMERAL } from "@bongtu/core/stealth";
import type { SubmitResult } from "@bongtu/client/rail";
import {
  confirmSignature,
  getAccountData,
  getLatestBlockhash,
  solanaExplorerTxUrl,
  type SolanaConnection,
} from "./connection/edge.js";
import {
  associatedTokenAccount,
  depositPrivInstruction,
  spendInstruction,
  withdrawPrivInstruction,
  type SolanaPoolAccounts,
} from "./txbuild/accounts.js";
import { transactionBudgetOf } from "./txbuild/budget.js";
import { encodeConsumerOpData, publicField, type ConsumerOpName } from "./txbuild/data.js";
import { assertTransactionSize } from "./txbuild/size.js";
import { appendedRoot, parseTreeState } from "./txbuild/tree.js";

/** What a Solana consumer session binds once: the pinned cluster, the pool's
 *  account record, and the optional per-deployment knobs. */
export interface SolanaConsumerConfig {
  /** the pinned cluster genesis hash (the ensureChain guard's reference). */
  genesisHash: string;
  /** the pool's static account set for this cluster. */
  accounts: SolanaPoolAccounts;
  /** the withdraw payout token account — REQUIRED before a withdraw submit
   *  (module doc: the io-construction-time binding, belt-checked in-proof). */
  withdrawTokenAccount?: string;
  /** TOTAL priority fee in lamports per transaction (the SIMD-0385 v1
   *  semantic, not a per-CU price; 0 = none). */
  priorityFeeLamports?: bigint;
  /** owner -> token account resolution (default: the associated token
   *  account of (owner, mint)). */
  tokenAccountOf?: (owner: string, mint: string) => Promise<string>;
}

/** The OPEN-3 truncate-253 binding, client side: a token account address read
 *  as a big-endian 256-bit integer with the top 3 bits cleared (addr mod
 *  2^253 — recipient_binding.rs). The value the withdraw WITNESS must carry
 *  as `recipient` (pass its decimal form as the flow's `withdrawTo`). */
export function boundWithdrawRecipient(tokenAccountBase58: string): string {
  const masked = Uint8Array.from(base58ToBytes(tokenAccountBase58));
  if (masked.length !== 32) throw new Error(`not a 32-byte address: ${tokenAccountBase58}`);
  masked[0] &= 0x1f;
  return masked.reduce<bigint>((acc, b) => (acc << 8n) | BigInt(b), 0n).toString();
}

/** u64 amount belt (per-rail narrowing, chains/solana README): SPL amounts
 *  are u64, and a proof-bound amount past that rejects AmountOverflow
 *  on-chain — fail readably here instead. */
function assertU64Amount(op: string, amount: bigint): void {
  if (amount >> 64n !== 0n) {
    throw new Error(`${op}: amount ${amount} exceeds u64 — SPL amounts are u64 on this rail`);
  }
}

/** The four consumer submits over one bound config — spread into the engine's
 *  flow deps via @bongtu/client-solana/ops solanaConsumerIo. */
export function solanaConsumerSubmits(cfg: SolanaConsumerConfig) {
  const priorityFee = cfg.priorityFeeLamports ?? 0n;
  const tokenAccountOf = cfg.tokenAccountOf ?? associatedTokenAccount;

  const treeHeadOf = async (connection: SolanaConnection) => {
    const data = await getAccountData(connection.rpcUrl, cfg.accounts.tree);
    if (data === null) throw new Error(`TreeState account ${cfg.accounts.tree} does not exist on this cluster`);
    return parseTreeState(data);
  };

  const sendOp = async (
    connection: SolanaConnection,
    op: ConsumerOpName,
    opIx: Instruction,
    explorerBase: string,
  ): Promise<SubmitResult> => {
    const lifetime = await getLatestBlockhash(connection.rpcUrl);
    // Version 1 (SIMD-0385): the ONLY format whose 4,096 B budget fits these
    // payloads (legacy/v0 stay capped at 1,232 B, which no op on this rail
    // fits, SOLR 3.1.2); needs Agave 4.2+ / @solana/kit 8+. On v1 the budget
    // is MANDATORY header config, not ComputeBudget instructions — an unset
    // CU or loaded-accounts field budgets ZERO and the op fails at execution
    // (txbuild/budget.ts owns the values).
    const message = appendTransactionMessageInstructions(
      [opIx],
      setTransactionMessageLifetimeUsingBlockhash(
        { blockhash: lifetime.blockhash as Blockhash, lastValidBlockHeight: lifetime.lastValidBlockHeight },
        setTransactionMessageConfig(
          transactionBudgetOf(op, priorityFee),
          setTransactionMessageFeePayer(connection.address as Address, createTransactionMessage({ version: 1 })),
        ),
      ),
    );
    const tx = compileTransaction(message);
    // One fee-payer signature: signatures shortvec(1) + 64 B + the compiled
    // message — the exact wire sendTransaction serializes.
    assertTransactionSize(op, {
      accountCount: opIx.accounts?.length ?? 0,
      dataLen: opIx.data?.length ?? 0,
      serializedLen: 1 + 64 + tx.messageBytes.length,
    });
    const signature = await connection.signAndSendTransaction(tx);
    await confirmSignature(connection.rpcUrl, signature);
    return { txHash: signature, explorerUrl: solanaExplorerTxUrl(signature, explorerBase) };
  };

  return {
    /** Submit a proven depositPriv (0-in / 2-out consumer mint): pulls the
     *  pub-bound amount from the payer's token account — the payer's tx
     *  signature IS the transfer authority, so no approve leg exists. */
    async submitDepositPriv(
      connection: SolanaConnection,
      calldata: Calldata,
      kemCiphertexts: string[],
      explorerBase: string,
    ): Promise<SubmitResult> {
      assertU64Amount("depositPriv", publicField("depositPriv", calldata, "amount")[0]);
      const head = await treeHeadOf(connection);
      const { root } = appendedRoot(head, publicField("depositPriv", calldata, "outputCommitments"));
      const ix = await depositPrivInstruction({
        accounts: cfg.accounts,
        payer: connection.address,
        payerTokenAccount: await tokenAccountOf(connection.address, cfg.accounts.mint),
        newRoot: root,
        data: encodeConsumerOpData("depositPriv", calldata, kemCiphertexts),
      });
      return sendOp(connection, "depositPriv", ix, explorerBase);
    },

    /** Submit a proven transferPriv (2-in / 2-out consumer spend). */
    submitTransferPriv(
      connection: SolanaConnection,
      calldata: Calldata,
      kemCiphertexts: string[],
      explorerBase: string,
    ): Promise<SubmitResult> {
      return submitSpend("transferPriv", connection, calldata, kemCiphertexts, explorerBase);
    },

    /** Submit a proven transfer10x2Priv (10-in / 2-out; every consumer merge
     *  leg) — the rail's tightest wire, which is what the pre-send size
     *  assertion is really for. */
    submitTransfer10x2Priv(
      connection: SolanaConnection,
      calldata: Calldata,
      kemCiphertexts: string[],
      explorerBase: string,
    ): Promise<SubmitResult> {
      return submitSpend("transfer10x2Priv", connection, calldata, kemCiphertexts, explorerBase);
    },

    /** Submit a proven withdrawPriv (2-in / 1-out change + proof-bound
     *  payout). Consumer v1 self-submits to a recipient the user chose, so
     *  the stealth announcement tail is the "nothing to announce" sentinel
     *  (zero ephemeral pub + tag 0 — byte-identical to the EVM wrapper). */
    async submitWithdrawPriv(
      connection: SolanaConnection,
      calldata: Calldata,
      kemCiphertexts: string[],
      explorerBase: string,
    ): Promise<SubmitResult> {
      const recipientToken = cfg.withdrawTokenAccount;
      if (recipientToken === undefined) {
        throw new Error(
          "withdrawPriv needs SolanaConsumerConfig.withdrawTokenAccount — the payout token account " +
            "is bound at io-construction time on this rail (see @bongtu/client-solana/consumer)",
        );
      }
      // The io-binding belt: the account we pass MUST be the one the proof
      // bound (the program injects truncate-253 of the meta into pub).
      const bound = publicField("withdrawPriv", calldata, "recipient")[0];
      if (BigInt(boundWithdrawRecipient(recipientToken)) !== bound) {
        throw new Error(
          `withdrawPriv: the proof binds recipient ${bound}, but withdrawTokenAccount ${recipientToken} ` +
            `truncates to ${boundWithdrawRecipient(recipientToken)} — re-prove or fix the io binding`,
        );
      }
      assertU64Amount("withdrawPriv", publicField("withdrawPriv", calldata, "amount")[0]);
      const head = await treeHeadOf(connection);
      const { root } = appendedRoot(head, publicField("withdrawPriv", calldata, "changeCommitment"));
      const stealthTail = zeroEphemeralTail();
      const ix = await withdrawPrivInstruction({
        accounts: cfg.accounts,
        payer: connection.address,
        recipientTokenAccount: recipientToken,
        spentRoot: publicField("withdrawPriv", calldata, "root")[0],
        newRoot: root,
        nullifiers: publicField("withdrawPriv", calldata, "nullifiers"),
        data: encodeConsumerOpData("withdrawPriv", calldata, kemCiphertexts, stealthTail),
      });
      return sendOp(connection, "withdrawPriv", ix, explorerBase);
    },
  };

  async function submitSpend(
    op: "transferPriv" | "transfer10x2Priv",
    connection: SolanaConnection,
    calldata: Calldata,
    kemCiphertexts: string[],
    explorerBase: string,
  ): Promise<SubmitResult> {
    const head = await treeHeadOf(connection);
    const { root } = appendedRoot(head, publicField(op, calldata, "outputCommitments"));
    const ix = await spendInstruction({
      accounts: cfg.accounts,
      payer: connection.address,
      spentRoot: publicField(op, calldata, "root")[0],
      newRoot: root,
      nullifiers: publicField(op, calldata, "nullifiers"),
      data: encodeConsumerOpData(op, calldata, kemCiphertexts),
    });
    return sendOp(connection, op, ix, explorerBase);
  }
}

/** The 33-byte "no announcement" stealth tail: ZERO_EPHEMERAL (32 zero
 *  bytes) + view tag 0 — all zero, so a fresh Uint8Array(33) already IS the
 *  bytes; the guard is the load-bearing part, failing loudly if the shared
 *  sentinel constant ever stops being zero. */
function zeroEphemeralTail(): Uint8Array {
  if (BigInt(ZERO_EPHEMERAL) !== 0n) {
    throw new Error("ZERO_EPHEMERAL is no longer zero — update the withdraw sentinel");
  }
  return new Uint8Array(33);
}
