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
import { classifyChainFailure, describeThrown } from "@bongtu/core/errors";

/**
 * The console's message for a failed wallet/RPC interaction. Delegates the two
 * verdicts the shared wallet wording already covers (user rejection, gas), and
 * words the rest itself. Anything the classifier cannot name falls through to
 * the engine's own words: a precise revert line beats a vague paraphrase.
 */
export function payrollErrorMessage(e: unknown): string {
  const failure = classifyChainFailure(e);
  switch (failure.kind) {
    case "chain_switch":
      return failure.rejected
        ? "Network switch rejected in your wallet. Switch to GIWA Sepolia and try again."
        : "Could not switch the wallet to GIWA Sepolia.";
    case "timeout":
      return "No response — the request timed out. Try again in a moment.";
    case "transport":
      return "Could not reach the network. Check your connection and try again.";
    default:
      return walletErrorMessage(e);
  }
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
