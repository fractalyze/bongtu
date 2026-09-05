// The consumer wallet's wording boundary for failed wallet/RPC interactions.
// The structural verdict comes from the SHARED classifier (@bongtu/core/errors),
// so this app and every sibling agree on WHAT happened; this module owns only
// the consumer's WORDS per verdict — a Record over the full ChainFailure union,
// so a kind added to the classifier is a tsc error here instead of a silent
// fall-through to raw provider text (the payroll errors.ts pattern).
//
// The delegating entries are deliberate: user rejection and the no-gas case
// already have plain-words wallet wording in the engine (walletErrorMessage —
// whose gas line carries the GAS_TOKEN_PHRASE the ErrorBanner keys its faucet
// link on), and `other` must pass the engine's own line through untouched: the
// flows wrap their failures with the money-state reassurance, and a paraphrase
// here would eat it.

import { walletErrorMessage } from "@bongtu/client-evm/connection";
import { classifyChainFailure, failureCopy, type FailureCopyTable } from "@bongtu/core/errors";
import { CHAIN_NAME } from "@bongtu/core/network";

export const CONSUMER_FAILURE_COPY: FailureCopyTable = {
  user_rejected: (_failure, e) => walletErrorMessage(e),
  insufficient_gas: (_failure, e) => walletErrorMessage(e),
  chain_switch: (failure) =>
    failure.rejected
      ? `Network switch rejected in your wallet. Switch to ${CHAIN_NAME} and try again.`
      : `Could not switch your wallet to ${CHAIN_NAME}.`,
  timeout: () => "No response. The network request timed out. Try again in a moment.",
  transport: () => "Could not reach the network. Check your connection and try again.",
  other: (_failure, e) => walletErrorMessage(e),
};

/** The consumer wallet's message for a failed wallet/RPC interaction, routed
 *  through the exhaustive table above. The op screens' one error edge. */
export function consumerErrorMessage(e: unknown): string {
  return failureCopy(CONSUMER_FAILURE_COPY, classifyChainFailure(e), e);
}
