// The console's wording boundary. The structural verdict on a failure comes from
// the SHARED classifier (@bongtu/core/errors) rather than from matching English
// text, so this app and the wallet agree on WHAT happened; this module owns the
// console's own words for the verdicts the shared walletErrorMessage doesn't
// cover (network switch, timeout, transport — a payroll operator hits these on a
// desk machine and needs the fix named). The engine's original line stays
// available as the Copy-details payload (error-surface class 5), so nothing is
// lost for a bug report.
//
// Everything here is pure — the wording gates under node:test (test/errors.test.ts).

import { walletErrorMessage } from "@bongtu/client/connection";
import { parseKkrw } from "@bongtu/client/money";
import { classifyChainFailure, describeThrown, failureCopy, type FailureCopyTable } from "@bongtu/core/errors";
import { CHAIN_NAME } from "@bongtu/core/network";

/**
 * The console's words per ChainFailure kind — a Record over the full union, so a
 * kind added to the shared classifier is a tsc error here instead of a silent
 * fall-through. The desk-machine failures (network switch, timeout, transport)
 * get the console's own words; the rest delegate to the shared wallet wording
 * (user rejection, gas, and the catch-all — where the engine's own line, a
 * precise revert, beats a vague paraphrase of it).
 */
export const PAYROLL_FAILURE_COPY: FailureCopyTable = {
  user_rejected: (_failure, e) => walletErrorMessage(e),
  insufficient_gas: (_failure, e) => walletErrorMessage(e),
  chain_switch: (failure) =>
    failure.rejected
      ? `Network switch rejected in your wallet. Switch to ${CHAIN_NAME} and try again.`
      : `Could not switch the wallet to ${CHAIN_NAME}.`,
  timeout: () => "No response — the request timed out. Try again in a moment.",
  transport: () => "Could not reach the network. Check your connection and try again.",
  other: (_failure, e) => walletErrorMessage(e),
};

/** The console's message for a failed wallet/RPC interaction, routed through the
 *  exhaustive table above. */
export function payrollErrorMessage(e: unknown): string {
  return failureCopy(PAYROLL_FAILURE_COPY, classifyChainFailure(e), e);
}

/** The full thrown value for the "Copy details" affordance. Details never leave the
 *  device except by the user's own paste — there is no error telemetry here. */
export function errorDetails(e: unknown): string {
  return describeThrown(e);
}

/**
 * parseKkrw's verdicts for the deposit field. The money grammar (comma grouping,
 * the 6-decimal cap, the 2^100 single-note belt) belongs to @bongtu/client/money
 * and is NOT re-implemented here — and since the console speaks English, its
 * per-cause messages are used verbatim. The seam stays (and stays tested) so a
 * wording collapse upstream — several causes falling into one vague line — fails
 * the gate here instead of reaching the deposit field unnoticed.
 */
export function parseDepositAmount(input: string): { ok: true; wei: bigint } | { ok: false; error: string } {
  return parseKkrw(input);
}
