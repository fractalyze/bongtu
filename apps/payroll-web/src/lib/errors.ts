// The console's KOREAN boundary. @bongtu/client and @bongtu/ui are shared with the
// (English) wallet, so their strings stay English and are never translated in
// place; this module maps the handful of failures a payroll operator can actually
// hit into the console's voice, at the app's own edge. The engine's original line
// stays available as the Copy-details payload (error-surface class 5), so nothing
// is lost for a bug report.
//
// Everything here is pure — the wording gates under node:test (test/errors.test.ts).

import { walletErrorMessage } from "@bongtu/client/connection";
import { parseKkrw } from "@bongtu/client/money";
import { classifyChainFailure, describeThrown } from "@bongtu/core/errors";

/**
 * Korean for a failed wallet/RPC interaction. The structural verdict comes from the
 * SHARED classifier (@bongtu/core/errors) rather than from matching English text,
 * so the two apps agree on WHAT happened and differ only in how they say it.
 *
 * Anything the classifier cannot name (a contract revert, an engine error that is
 * already Korean) falls through to the engine's own words: a precise English
 * sentence beats a vague Korean one, and a Korean message passes through unharmed.
 */
export function payrollErrorMessage(e: unknown): string {
  const failure = classifyChainFailure(e);
  switch (failure.kind) {
    case "user_rejected":
      return "지갑에서 서명을 거부했습니다.";
    case "chain_switch":
      return failure.rejected
        ? "지갑에서 네트워크 전환을 거부했습니다. GIWA Sepolia로 전환한 뒤 다시 시도하세요."
        : "지갑을 GIWA Sepolia 네트워크로 전환하지 못했습니다.";
    case "insufficient_gas":
      return "가스로 낼 GIWA Sepolia ETH가 부족합니다. 이 계정에 ETH를 조금 채워주세요.";
    case "timeout":
      return "응답이 없어 시간이 초과되었습니다. 잠시 후 다시 시도하세요.";
    case "transport":
      return "네트워크에 연결하지 못했습니다. 연결 상태를 확인하고 다시 시도하세요.";
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
 * parseKkrw's verdicts in the deposit field's voice.
 *
 * The money grammar (comma grouping, the 6-decimal cap, the 2^100 single-note
 * belt) belongs to @bongtu/client/money and is NOT re-implemented here — only its
 * English answers are re-worded. Matching on those answers is a coupling, so the
 * test drives real inputs through this function and asserts a distinct Korean line
 * for each: a reword upstream fails the gate rather than silently falling back.
 */
const AMOUNT_ERROR_KO: [RegExp, string][] = [
  [/thousands separators/i, "쉼표는 천단위 구분에만 쓰고, 소수점은 마침표로 입력하세요. 예: 1,000.5"],
  [/decimal places/i, "소수점 이하 6자리까지만 입력할 수 있습니다."],
  [/too large/i, "한 번에 입금할 수 있는 금액을 넘었습니다."],
  [/Enter an amount/i, "금액을 입력하세요."],
];

export function parseDepositAmount(input: string): { ok: true; wei: bigint } | { ok: false; error: string } {
  const parsed = parseKkrw(input);
  if (parsed.ok) return parsed;
  const hit = AMOUNT_ERROR_KO.find(([pattern]) => pattern.test(parsed.error));
  return { ok: false, error: hit ? hit[1] : "올바른 금액이 아닙니다. 예: 1000 또는 1.5" };
}
