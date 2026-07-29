// Random recipient generation — the testnet tool's payee source. The console is
// a TEST console: instead of typing 255 payees, the operator clicks one button
// and gets a full worksheet of fresh, valid, distinct bjj addresses with random
// integer kKRW amounts that together land at ~80% of the current balance.
//
// The rules this module owns (headlessly gated in test/randomRecipients.test.ts):
//
//   - addresses are REAL BabyJubJub keys: a random 31-byte scalar from the
//     CSPRNG (crypto.getRandomValues) -> deriveKeypair -> packPubkey, the same
//     @bongtu/core path a wallet uses — every generated address decodes, and a
//     duplicate draw is redrawn, so rows never trip the worksheet's dup check;
//   - amounts are whole kKRW, minimum 1 per row, and their SUM is exactly the
//     target: floor(80% of the whole-kKRW balance). target <= 0.8 * balance, so
//     the total is always strictly below the balance — generation can never
//     produce an insufficient sheet on its own;
//   - row count: 255 (B−1, the disburse cap) when the target covers it, else
//     the target itself — a balance too small for 255 rows of >= 1 kKRW makes
//     FEWER rows rather than sub-1 amounts (documented rule: rowCount =
//     min(255, targetKkrw)). A target of zero (balance < 2 kKRW, or unknown)
//     means generation is disabled; a known-too-small balance shows the
//     "Deposit first" hint (an UNKNOWN balance shows Loading instead).

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { MAX_ROWS, type WorksheetRow } from "./worksheet.js";

const KKRW = 10n ** 18n;

/** The generated total's share of the balance: ~80%, computed floor(b * 4/5)
 *  on whole kKRW so the sum stays an integer and strictly under the balance. */
const TARGET_NUM = 4n;
const TARGET_DEN = 5n;

/** The whole-kKRW total a generation run will distribute (sub-kKRW dust in the
 *  balance is ignored — amounts are integers). */
export function targetKkrw(balanceWei: bigint): bigint {
  return ((balanceWei / KKRW) * TARGET_NUM) / TARGET_DEN;
}

/**
 * How many rows a generation run would produce for this balance — 0 means
 * generation is not possible (unknown balance, or a target below 1 kKRW) and
 * the generate button must be disabled — with the "Deposit first" hint when
 * the balance is known-too-small (unknown balance renders Loading, not the hint).
 */
export function plannedRowCount(balanceWei: bigint | null): number {
  if (balanceWei === null || balanceWei <= 0n) return 0;
  const target = targetKkrw(balanceWei);
  return target >= BigInt(MAX_ROWS) ? MAX_ROWS : Number(target);
}

/** A fresh random scalar in (0, 2^248) — 31 CSPRNG bytes, always below the
 *  BabyJubJub base-field prime (~2^254), never zero. */
function randomScalar(): bigint {
  for (;;) {
    const bytes = new Uint8Array(31);
    crypto.getRandomValues(bytes);
    let scalar = 0n;
    for (const b of bytes) scalar = (scalar << 8n) | BigInt(b);
    if (scalar !== 0n) return scalar;
  }
}

/** One uniform-ish index in [0, n) for leftover hand-out (single Uint32 mod n —
 *  the bias is immaterial for distributing < n leftover units of test money). */
function randomIndex(n: number): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % n;
}

/** Split `total` whole kKRW over `n` rows: 1 each, the rest by random 32-bit
 *  weights, floor-rounding leftovers handed to random rows — sums EXACTLY. */
function splitAmounts(total: bigint, n: number): bigint[] {
  const rest = total - BigInt(n);
  const raw = new Uint32Array(n);
  crypto.getRandomValues(raw);
  const weights = Array.from(raw, (x) => BigInt(x) + 1n);
  const weightSum = weights.reduce((s, w) => s + w, 0n);
  const amounts = weights.map((w) => 1n + (rest * w) / weightSum);
  let leftover = total - amounts.reduce((s, a) => s + a, 0n); // 0 <= leftover < n
  while (leftover > 0n) {
    amounts[randomIndex(n)] += 1n;
    leftover -= 1n;
  }
  return amounts;
}

/**
 * Generate the whole test worksheet for `balanceWei`: plannedRowCount rows of
 * fresh distinct addresses and random integer amounts summing to targetKkrw.
 * Throws when plannedRowCount is 0 — the view must gate the button, not catch.
 */
export function generateRecipients(balanceWei: bigint): WorksheetRow[] {
  const count = plannedRowCount(balanceWei);
  if (count === 0) {
    throw new Error("The balance is too small to generate a test payroll. Deposit first.");
  }
  const amounts = splitAmounts(targetKkrw(balanceWei), count);
  const seen = new Set<string>();
  const rows: WorksheetRow[] = [];
  for (let i = 0; i < count; i++) {
    let address: string;
    do {
      address = packPubkey(deriveKeypair(randomScalar()).publicKey);
    } while (seen.has(address));
    seen.add(address);
    rows.push({ address, amount: amounts[i].toString() });
  }
  return rows;
}
