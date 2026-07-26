// The ONE UI-edge money layer for kKRW (the on-chain token has decimals()=18, matching
// MetaMask). The protocol layer — notes, witness inputs, contract calldata, indexer
// values — speaks RAW WEI ONLY and must never change; every human-facing render goes
// through formatKkrw and every typed amount through parseKkrw, both BigInt string math
// (Number/parseFloat would silently lose precision on 18-decimal values).

const WEI_PER_KKRW = 10n ** 18n;

/** Display fraction digits: ALWAYS exactly 6, truncated (floored), trailing zeros kept. */
const DISPLAY_FRACTION_DIGITS = 6;

/** Circuit CheckPositive belt: every note value is range-checked below 2^100, so any
 *  amount at or above this must be rejected BEFORE a multi-second proof is started. */
export const MAX_NOTE_WEI = 1n << 100n;

export const MAX_UINT256 = (1n << 256n) - 1n;

/**
 * Render raw wei as whole kKRW: integer part thousands-grouped, then exactly 6
 * fraction digits TRUNCATED beyond the 6th (never rounded — rounding could display
 * more than the user actually holds). 1e11 wei of dust renders "0.000000".
 */
export function formatKkrw(raw: string | bigint): string {
  let v = typeof raw === "bigint" ? raw : BigInt(raw);
  const neg = v < 0n;
  if (neg) v = -v;
  const whole = (v / WEI_PER_KKRW).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const frac = (v % WEI_PER_KKRW).toString().padStart(18, "0").slice(0, DISPLAY_FRACTION_DIGITS);
  return `${neg ? "-" : ""}${whole}.${frac}`;
}

export type ParsedKkrw = { ok: true; wei: bigint } | { ok: false; error: string };

/**
 * Parse a hand-typed kKRW amount ("1,000", "1.5", ".25" is rejected) to raw wei.
 * At most 6 fraction digits are accepted — beyond MetaMask-style display precision a
 * typo is far likelier than intent, and rejecting keeps parse(format(x)) lossless.
 * The 2^100 belt is enforced here so an over-range note never reaches the prover.
 */
export function parseKkrw(input: string): ParsedKkrw {
  const t = input.trim();
  if (!t) return { ok: false, error: "Enter an amount." };
  // Commas are accepted ONLY as strict 3-digit grouping ("1,000,000.5") — a
  // comma-as-decimal habit ("1,5") would otherwise silently parse 10x too large.
  if (t.includes(",") && !/^\d{1,3}(,\d{3})+(\.\d*)?$/.test(t)) {
    return { ok: false, error: "Use commas only as thousands separators, and a period for decimals." };
  }
  const v = t.replace(/,/g, "");
  const m = /^(\d+)(?:\.(\d*))?$/.exec(v);
  if (!m) return { ok: false, error: "Enter a valid amount, like 1000 or 1.5." };
  const frac = m[2] ?? "";
  if (frac.length > DISPLAY_FRACTION_DIGITS) {
    return { ok: false, error: "Use at most 6 decimal places." };
  }
  const wei = BigInt(m[1]) * WEI_PER_KKRW + BigInt(frac.padEnd(18, "0") || "0");
  if (wei >= MAX_NOTE_WEI) {
    return { ok: false, error: "Amount is too large for a single note (max ~1.26 trillion kKRW)." };
  }
  return { ok: true, wei };
}

/** The allowance line: an unlimited (MaxUint256) approval reads "Unlimited" — the
 *  78-digit number is meaningless to render; anything else follows the 6-decimal policy. */
export function allowanceLabel(allowance: bigint): string {
  return allowance === MAX_UINT256 ? "Unlimited" : formatKkrw(allowance);
}
