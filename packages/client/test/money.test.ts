// Headless gates for the UI-edge money layer (src/money.ts) — the ONLY place raw
// wei becomes a human kKRW string and back. Locked policy under test:
//
//   (1) FORMAT — raw / 10^18, up to 6 fraction digits TRUNCATED beyond 6 (never
//       rounded) with trailing zeros trimmed, thousands grouping on the integer part,
//       BigInt string math only (dust below 10^12 wei must render 0, not 1e-7).
//   (2) PARSE — decimal input with at most 6 fraction digits to exact raw wei;
//       >6 digits / garbage / empty rejected with clear messages; the circuit
//       CheckPositive belt (note value < 2^100 wei) enforced BEFORE proving.
//   (3) ALLOWANCE LABEL — MaxUint256 reads "Unlimited" (never a 78-digit number);
//       any ordinary value follows the same 6-decimal display policy.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  formatKkrw,
  amountCaretIndex,
  groupAmountInput,
  parseKkrw,
  allowanceLabel,
  MAX_NOTE_WEI,
  MAX_UINT256,
} from "../src/money.js";

const WEI = 10n ** 18n;

function parsedWei(input: string): bigint {
  const p = parseKkrw(input);
  assert.ok(p.ok, `expected "${input}" to parse, got ${p.ok ? "" : p.error}`);
  return p.wei;
}

// ============================ (1) FORMAT ====================================

test("formatKkrw: the locked example vectors", () => {
  assert.equal(formatKkrw(1_000_000n * WEI), "1,000,000");
  assert.equal(formatKkrw(15n * 10n ** 17n), "1.5"); // 1.5e18
  assert.equal(formatKkrw(10n ** 11n), "0"); // 1e11 wei dust floors to zero
  assert.equal(formatKkrw(0n), "0");
});

test("formatKkrw trims trailing zeros and the dangling point", () => {
  assert.equal(formatKkrw(1_000n * WEI), "1,000"); // not "1,000.000000"
  assert.equal(formatKkrw(1_000n * WEI + 5n * 10n ** 17n), "1,000.5"); // not "1,000.500000"
  // an interior zero is significant — only the TRAILING run goes.
  assert.equal(formatKkrw(WEI + 10n ** 12n), "1.000001");
  assert.equal(formatKkrw(WEI + 105n * 10n ** 13n), "1.00105");
});

test("formatKkrw truncates beyond 6 decimals — never rounds", () => {
  // 1.9999999 kKRW: rounding would show 2.000000 (more than the user holds).
  assert.equal(formatKkrw(1_999_999_900_000_000_000n), "1.999999");
  // all-9 fraction: still floors.
  assert.equal(formatKkrw(999_999_999_999_999_999n), "0.999999");
  // one wei below a whole unit is NOT a whole unit.
  assert.equal(formatKkrw(WEI - 1n), "0.999999");
});

test("formatKkrw groups the integer part", () => {
  assert.equal(formatKkrw(1_234_567_890n * WEI), "1,234,567,890");
  assert.equal(formatKkrw(1_234n * WEI + 5n * 10n ** 17n), "1,234.5");
  assert.equal(formatKkrw(123n * WEI), "123");
});

test("formatKkrw accepts decimal-string raw values (indexer amounts are strings)", () => {
  assert.equal(formatKkrw((250n * WEI).toString()), "250");
});

// ============================ (2) PARSE =====================================

test("parseKkrw: integer input scales by 10^18", () => {
  assert.equal(parsedWei("1000000"), 1_000_000n * WEI);
  assert.equal(parsedWei("1"), WEI);
  // thousands separators are tolerated (users paste formatted values back).
  assert.equal(parsedWei("1,000,000"), 1_000_000n * WEI);
  assert.equal(parsedWei("1,000,000.5"), 1_000_000n * WEI + WEI / 2n);
});

test("parseKkrw: commas must be strict 3-digit grouping — a decimal-comma habit is rejected", () => {
  // "1,5" as strip-all-commas would parse 15 kKRW: a silent 10x over-send.
  for (const s of ["1,5", "1,00", "12,34", "1,0000", ",100"]) {
    const r = parseKkrw(s);
    assert.equal(r.ok, false, `${s} must be rejected`);
    if (!r.ok) assert.match(r.error, /thousands separators/);
  }
});

test("formatKkrw renders negative values with a leading minus", () => {
  assert.equal(formatKkrw(-15n * 10n ** 17n), "-1.5");
});

test("parseKkrw: up to 6 fraction digits parse to exact raw wei", () => {
  assert.equal(parsedWei("1.5"), 15n * 10n ** 17n);
  assert.equal(parsedWei("0.000001"), 10n ** 12n); // the smallest typable amount
  assert.equal(parsedWei("123.456789"), 123_456_789n * 10n ** 12n);
});

test("parseKkrw rejects more than 6 fraction digits with a clear message", () => {
  const p = parseKkrw("1.0000001");
  assert.equal(p.ok, false);
  assert.match(!p.ok ? p.error : "", /6 decimal/i);
});

test("parseKkrw rejects empty and garbage input", () => {
  for (const bad of ["", "   ", "abc", "1.2.3", "1e18", "-5", ".", ".5", "1..2"]) {
    const p = parseKkrw(bad);
    assert.equal(p.ok, false, `"${bad}" must not parse`);
    assert.ok(!p.ok && p.error.length > 0, "rejection carries a message");
  }
});

test("parseKkrw round-trips with formatKkrw exactly (canonical strings)", () => {
  for (const s of ["1,000,000", "1.5", "0.000001", "123.456789", "0"]) {
    assert.equal(formatKkrw(parsedWei(s)), s);
    assert.equal(parsedWei(formatKkrw(parsedWei(s))), parsedWei(s));
  }
});

test("parseKkrw enforces the 2^100 note-value belt before proving", () => {
  // the largest whole-kKRW amount under the belt: floor((2^100 - 1) / 10^18).
  const maxWhole = (MAX_NOTE_WEI - 1n) / WEI;
  assert.equal(parsedWei(maxWhole.toString()), maxWhole * WEI);
  const over = parseKkrw((maxWhole + 1n).toString());
  assert.equal(over.ok, false);
  assert.match(!over.ok ? over.error : "", /too large/i);
  // sanity: the belt bound is the circuit's CheckPositive range (2^100).
  assert.equal(MAX_NOTE_WEI, 1n << 100n);
});

// ==================== (2b) LIVE-TYPING NORMALIZER ===========================
// groupAmountInput is what AmountInput runs on EVERY keystroke: it must group
// live, keep exactly one decimal point, strip junk, trim leading zeros, and —
// the locked invariant — never emit a string that trips parseKkrw's strict
// comma-grouping rule (typing can't manufacture the comma error).

test("groupAmountInput: thousands-groups the integer part while typing", () => {
  // the keystroke sequence for "1234567" — every intermediate stays grouped
  assert.equal(groupAmountInput("1"), "1");
  assert.equal(groupAmountInput("12"), "12");
  assert.equal(groupAmountInput("123"), "123");
  assert.equal(groupAmountInput("1234"), "1,234");
  assert.equal(groupAmountInput("1,2345"), "12,345"); // regroups a now-stale comma
  assert.equal(groupAmountInput("1,234,567"), "1,234,567"); // already-clean is a fixpoint
});

test("groupAmountInput: keeps a single decimal point, fraction ungrouped", () => {
  assert.equal(groupAmountInput("1.5"), "1.5");
  assert.equal(groupAmountInput("1234.5678"), "1,234.5678");
  assert.equal(groupAmountInput("1234."), "1,234."); // mid-typing trailing dot survives
  assert.equal(groupAmountInput("1.2.3"), "1.23"); // extra dots collapse into the fraction
});

test("groupAmountInput: strips junk, trims leading zeros", () => {
  assert.equal(groupAmountInput("abc12x3!"), "123");
  assert.equal(groupAmountInput("₩1,000 kKRW"), "1,000");
  assert.equal(groupAmountInput("007"), "7");
  assert.equal(groupAmountInput("000.5"), "0.5"); // one zero kept before the dot
  assert.equal(groupAmountInput("0"), "0");
  assert.equal(groupAmountInput(""), "");
});

test("groupAmountInput: output never trips parseKkrw's comma-grouping rule", () => {
  // Junky/partial inputs may parse-fail (empty, bare dot) but NEVER with the
  // comma error — the normalizer's whole reason to exist.
  const inputs = ["", ".", "1", "1,2345", "12345678", "1,234,567.89", "0007.25", "1.2.3", "abc", "9,9"];
  for (const raw of inputs) {
    const out = groupAmountInput(raw);
    const p = parseKkrw(out);
    if (!p.ok) assert.doesNotMatch(p.error, /thousands separators/i, `input "${raw}" -> "${out}"`);
  }
  // and a well-formed typed amount round-trips to the exact wei
  const p = parseKkrw(groupAmountInput("1234567.25"));
  assert.ok(p.ok);
  assert.equal(p.ok ? p.wei : 0n, 1_234_567n * WEI + (WEI / 4n));
});

// ============================ (3) ALLOWANCE LABEL ===========================

test("allowanceLabel: MaxUint256 reads Unlimited, ordinary values are formatted", () => {
  assert.equal(allowanceLabel(MAX_UINT256), "Unlimited");
  assert.equal(MAX_UINT256, (1n << 256n) - 1n);
  assert.equal(allowanceLabel(0n), "0");
  assert.equal(allowanceLabel(1_000_000n * WEI), "1,000,000");
  // one below MaxUint is NOT unlimited — it renders under the same display policy
  // (huge, but a finite grouped number — never the raw 78-digit integer).
  const nearMax = allowanceLabel(MAX_UINT256 - 1n);
  assert.notEqual(nearMax, "Unlimited");
  assert.match(nearMax, /^[\d,]+(\.\d{1,6})?$/);
});

test("amountCaretIndex: caret lands after the same significant char across regrouping", () => {
  // "1234" caret after "12" (2 significant) → "1,234" index 3 (after the '2').
  assert.equal(amountCaretIndex("1,234", 2), 3);
  // start / zero significants
  assert.equal(amountCaretIndex("1,234", 0), 0);
  // beyond the end clamps to length
  assert.equal(amountCaretIndex("1,234", 99), 5);
  // dot counts as significant: "1,234.5" after 5 significants (1234.) → index 6
  assert.equal(amountCaretIndex("1,234.5", 5), 6);
  // full string
  assert.equal(amountCaretIndex("12", 2), 2);
});
