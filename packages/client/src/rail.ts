// The engine's structural rail seam (issue #40). This package is the
// rail-agnostic engine: scan, plan/build, the prove+submit orchestrations and
// the facades — none of it may import a rail SDK (viem, a Solana SDK) or a rail
// client package. The shapes the engine actually consumes from a rail are
// declared HERE, and a rail client (@bongtu/client-evm today, the Solana client
// next) satisfies them structurally: its own Connection carries the rail's
// clients ON TOP of the seam shape below, and its submit/guard functions match
// the per-flow io interfaces (ops/deposit.ts, ops/spend/run.ts,
// ops/consumer/run.ts, session/login.ts). Those io members are declared
// METHOD-style on purpose — method parameters are checked bivariantly, so a
// rail implementation typed over its own wider Connection is assignable to the
// seam without a cast.

import { classifyChainFailure, fallbackText, failureCopy, type FailureCopyTable } from "@bongtu/core/errors";
import { CHAIN_NAME, GAS_TOKEN_PHRASE, NATIVE_CURRENCY } from "@bongtu/core/network";
import type { WalletTransport } from "@bongtu/client/session";

/**
 * A connected wallet, as the ENGINE sees it: the two facts every rail exposes.
 * The rail client's own Connection (e.g. @bongtu/client-evm/connection) extends
 * this shape with its SDK clients; the engine threads the value through to the
 * rail io opaquely and reads only these members itself.
 */
export interface Connection {
  /** the account, as the rail edge reported it at connect time (frozen). */
  address: string;
  /** How the browser reached this wallet. The flows ignore it; the login guard
   *  doesn't (a remote wallet gets a different determinism rule). */
  transport: WalletTransport;
}

/** What every rail submit resolves to: the tx and its explorer link. */
export interface SubmitResult {
  txHash: string;
  explorerUrl: string;
}

/** The depositor's raw kKRW balance and current allowance to the pool. */
export interface TokenState {
  balance: bigint;
  allowance: bigint;
}

/**
 * The wallet's words per ChainFailure kind. The structural digging (cause chain,
 * conventional fields, viem's typed error names) lives in the shared classifier
 * (@bongtu/core/errors classifyChainFailure); this table is only the wallet's
 * WORDS for each verdict. A Record over the full union, so a kind added to the
 * classifier is a tsc error HERE rather than a silent fall-through to raw viem
 * text. Only the failures every tester hits (user rejection, no gas ETH, a
 * declined switch) get wallet wording; the rest keep viem's own best line via
 * the shared fallbackText — a precise revert beats any paraphrase.
 */
export const WALLET_FAILURE_COPY: FailureCopyTable = {
  user_rejected: () => "Transaction rejected in your wallet.",
  insufficient_gas: () =>
    `Not enough ${GAS_TOKEN_PHRASE} to pay gas. This account needs a little ${NATIVE_CURRENCY.symbol} on ${CHAIN_NAME} first.`,
  // an un-rejected switch failure reads best in viem's own words
  chain_switch: (failure, e) =>
    failure.rejected ? "Transaction rejected in your wallet." : fallbackText(failure, e),
  timeout: fallbackText,
  transport: fallbackText,
  other: fallbackText,
};

export function walletErrorMessage(e: unknown): string {
  return failureCopy(WALLET_FAILURE_COPY, classifyChainFailure(e), e);
}
