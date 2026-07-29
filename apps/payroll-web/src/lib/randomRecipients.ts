// Random recipient generation — the testnet tool's payee source. The console is
// a TEST console: instead of typing 255 payees, the operator clicks one button
// and gets a full worksheet of fresh, valid, distinct bjj addresses with random
// integer kKRW amounts that together land at ~80% of the current balance.
//
// The rules this module owns (headlessly gated in test/randomRecipients.test.ts):
//
//   - addresses are REAL BabyJubJub subgroup points: a run derives TWO random
//     keypairs (CSPRNG scalar -> deriveKeypair, the same @bongtu/core path a
//     wallet uses) and walks P += step from there — one point ADDITION per row
//     instead of a full scalar mult (which costs ~50ms each, 13 s for a
//     255-row sheet, measured; the payees are throwaway test identities whose
//     private keys are discarded, so the rows being an arithmetic walk is
//     immaterial). Every address packs/decodes exactly like a wallet's, and a
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

import { addPoint, type Point } from "@bongtu/core/babyjub";
import { deriveKeypair } from "@bongtu/core/note";
import { encodeAddress, packPubkey } from "@bongtu/core/pubkey";
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
  const next = addressStream();
  return amounts.map((a) => ({ address: next(), amount: a.toString() }));
}

/** Fresh distinct base58 addresses, one point ADDITION each: both generators
 *  share this because the alternative — a full scalar mult per row — is the
 *  13-seconds-per-sheet cost the module doc rules out. */
function addressStream(): () => string {
  let p: Point = deriveKeypair(randomScalar()).publicKey;
  const step: Point = deriveKeypair(randomScalar()).publicKey;
  const seen = new Set<string>();
  return () => {
    for (;;) {
      const address = encodeAddress(packPubkey(p));
      p = addPoint(p, step);
      if (!seen.has(address)) {
        seen.add(address);
        return address;
      }
    }
  };
}

/**
 * The same sheet as generateRecipients, delivered in chunks with an event-loop
 * yield between them, so the view keeps painting and can append rows as they
 * arrive even on a machine where the point walk is not instant. `yieldFn` is
 * injectable so tests run without timers.
 */
export async function generateRecipientsChunked(
  balanceWei: bigint,
  onChunk: (chunk: WorksheetRow[]) => void,
  chunkSize = 32,
  yieldFn: () => Promise<void> = () => new Promise((r) => setTimeout(r, 0)),
): Promise<void> {
  const count = plannedRowCount(balanceWei);
  if (count === 0) {
    throw new Error("The balance is too small to generate a test payroll. Deposit first.");
  }
  // Yield BEFORE any field work: the caller's spinner setState has not painted
  // yet when this promise body starts, and the stream's two scalar mults are
  // the single heaviest slice — running them pre-paint reads as a dead click.
  await yieldFn();
  const amounts = splitAmounts(targetKkrw(balanceWei), count);
  const next = addressStream();
  for (let start = 0; start < count; start += chunkSize) {
    const end = Math.min(start + chunkSize, count);
    const chunk: WorksheetRow[] = [];
    for (let i = start; i < end; i++) {
      chunk.push({ address: next(), amount: amounts[i].toString() });
    }
    onChunk(chunk);
    if (end < count) await yieldFn();
  }
}
