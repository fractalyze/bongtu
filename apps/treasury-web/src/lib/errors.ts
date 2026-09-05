// The wallet's wording boundary for failed wallet/RPC interactions. The
// structural verdict comes from the SHARED classifier (@bongtu/core/errors),
// so this app and every sibling agree on WHAT happened; this module owns only
// the wallet's WORDS per verdict — a Record over the full ChainFailure union,
// so a kind added to the classifier is a tsc error here instead of a silent
// fall-through to raw provider text (the payroll/consumer errors.ts pattern;
// this app was the one sibling still calling the engine's walletErrorMessage
// raw, issue #45).
//
// The delegating entries are deliberate: user rejection and the no-gas case
// already have plain-words wallet wording in the engine (walletErrorMessage —
// whose gas line carries the GAS_TOKEN_PHRASE the error surfaces key on), and
// `other` must pass the engine's own line through untouched: the flows wrap
// their failures with the money-state reassurance, and a paraphrase here
// would eat it.

import { walletErrorMessage } from "@bongtu/client/connection";
import { classifyChainFailure, failureCopy, type FailureCopyTable } from "@bongtu/core/errors";
import { CHAIN_NAME } from "@bongtu/core/network";

export const TREASURY_FAILURE_COPY: FailureCopyTable = {
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

/** The wallet's message for a failed wallet/RPC interaction, routed through
 *  the exhaustive table above. The op screens' one error edge. */
export function treasuryErrorMessage(e: unknown): string {
  return failureCopy(TREASURY_FAILURE_COPY, classifyChainFailure(e), e);
}
