// Headless gate for the testnet tool's payee generator (lib/randomRecipients.ts).
// The invariants pinned here are the ones a broken generator would violate
// SILENTLY on chain: an invalid or duplicate address burns money into an
// unspendable slot, a sum at/over the balance makes every generated sheet
// insufficient, and a zero amount is rejected by the circuit only at prove time.

import { test } from "node:test";
import assert from "node:assert/strict";

import { decodeAddress } from "@bongtu/core/pubkey";
import { generateRecipients, generateRecipientsChunked, plannedRowCount, targetKkrw } from "../src/lib/randomRecipients.js";
import { MAX_ROWS, checkWorksheet } from "../src/lib/worksheet.js";

const KKRW = 10n ** 18n;

test("a funded balance generates EXACTLY 255 distinct valid rows summing to the 80% target", () => {
  const balance = 1_000_000n * KKRW;
  const rows = generateRecipients(balance);
  assert.equal(rows.length, 255, "255 = B-1, the disburse recipient cap");

  // every address is a real, decodable bjj address — and all 255 are distinct
  const canonical = rows.map((r) => decodeAddress(r.address));
  assert.equal(new Set(canonical).size, 255);

  // amounts are positive INTEGER kKRW (min 1 per row)
  for (const r of rows) assert.match(r.amount, /^[1-9]\d*$/);

  // the sum is exactly floor(80% of the whole-kKRW balance) — and therefore
  // always strictly below the balance
  const sum = rows.reduce((s, r) => s + BigInt(r.amount), 0n);
  assert.equal(sum, targetKkrw(balance));
  assert.equal(sum, 800_000n);
  assert.ok(sum * KKRW < balance);

  // the worksheet validator accepts every generated row as-is
  const check = checkWorksheet(rows);
  assert.deepEqual(check.issues, []);
  assert.equal(check.filledCount, 255);
  assert.equal(check.totalWei, sum * KKRW);
});

test("the total stays strictly below the balance even when the balance is not kKRW-round", () => {
  const balance = 1_000_000n * KKRW + 123456789n; // sub-kKRW dust ignored
  const rows = generateRecipients(balance);
  const sumWei = rows.reduce((s, r) => s + BigInt(r.amount), 0n) * KKRW;
  assert.ok(sumWei < balance);
  assert.equal(sumWei, targetKkrw(balance) * KKRW);
});

test("a balance too small for 255 rows generates FEWER rows, min 1 kKRW each (rowCount = min(255, target))", () => {
  const rows = generateRecipients(100n * KKRW); // target = 80 kKRW < 255
  assert.equal(rows.length, 80);
  const sum = rows.reduce((s, r) => s + BigInt(r.amount), 0n);
  assert.equal(sum, 80n);
  for (const r of rows) assert.equal(r.amount, "1", "an 80-kKRW target over 80 rows is 1 each");
});

test("zero/unknown/dust balances plan ZERO rows (the generate button's disable rule) and generation refuses", () => {
  assert.equal(plannedRowCount(null), 0, "unknown balance never generates against a guess");
  assert.equal(plannedRowCount(0n), 0);
  assert.equal(plannedRowCount(1n * KKRW), 0, "target floor(1*4/5)=0 — cannot fund even one 1-kKRW row");
  assert.equal(plannedRowCount(2n * KKRW), 1);
  assert.equal(plannedRowCount(1_000_000n * KKRW), MAX_ROWS);
  assert.throws(() => generateRecipients(0n), /Deposit first/);
});

test("regenerate REPLACES the sheet: two runs over the same balance share no address", () => {
  const balance = 10_000n * KKRW;
  const a = new Set(generateRecipients(balance).map((r) => r.address));
  const b = generateRecipients(balance).map((r) => r.address);
  // 248-bit CSPRNG scalars: any overlap means the generator is not drawing fresh
  assert.ok(b.every((addr) => !a.has(addr)));
});

test("chunked generation streams the SAME invariants: 255 distinct rows, exact sum", async () => {
  const balance = 1000n * 10n ** 18n;
  const chunks: number[] = [];
  const rows: { address: string; amount: string }[] = [];
  await generateRecipientsChunked(balance, (c) => { chunks.push(c.length); rows.push(...c); }, 32, async () => {});
  assert.equal(rows.length, 255);
  assert.ok(chunks.length > 1, "delivery is actually chunked");
  assert.equal(new Set(rows.map((r) => decodeAddress(r.address))).size, 255);
  const total = rows.reduce((s, r) => s + BigInt(r.amount), 0n);
  assert.equal(total, 800n, "sum is exactly floor(80%) of 1000 kKRW");
});
