// Headless gates for the UI-edge money layer (src/lib/money.ts) — the ONLY place raw
// wei becomes a human kKRW string and back. Locked policy under test:
//
//   (1) FORMAT — raw / 10^18, ALWAYS exactly 6 fraction digits (trailing zeros kept),
//       TRUNCATED beyond 6 (never rounded), thousands grouping on the integer part,
//       BigInt string math only (dust below 10^12 wei must render 0.000000, not 1e-7).
//   (2) PARSE — decimal input with at most 6 fraction digits to exact raw wei;
//       >6 digits / garbage / empty rejected with clear messages; the circuit
//       CheckPositive belt (note value < 2^100 wei) enforced BEFORE proving.
//   (3) ALLOWANCE LABEL — MaxUint256 reads "Unlimited" (never a 78-digit number);
//       any ordinary value follows the same 6-decimal display policy.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  formatKkrw,
  parseKkrw,
  allowanceLabel,
  MAX_NOTE_WEI,
  MAX_UINT256,
} from "../src/lib/money.js";

const WEI = 10n ** 18n;

function parsedWei(input: string): bigint {
  const p = parseKkrw(input);
  assert.ok(p.ok, `expected "${input}" to parse, got ${p.ok ? "" : p.error}`);
  return p.wei;
}

// ============================ (1) FORMAT ====================================

test("formatKkrw: the locked example vectors", () => {
  assert.equal(formatKkrw(1_000_000n * WEI), "1,000,000.000000");
  assert.equal(formatKkrw(15n * 10n ** 17n), "1.500000"); // 1.5e18
  assert.equal(formatKkrw(10n ** 11n), "0.000000"); // 1e11 wei dust floors to zero
  assert.equal(formatKkrw(0n), "0.000000");
});

test("formatKkrw truncates beyond 6 decimals — never rounds", () => {
  // 1.9999999 kKRW: rounding would show 2.000000 (more than the user holds).
  assert.equal(formatKkrw(1_999_999_900_000_000_000n), "1.999999");
  // all-9 fraction: still floors.
  assert.equal(formatKkrw(999_999_999_999_999_999n), "0.999999");
  // one wei below a whole unit is NOT a whole unit.
  assert.equal(formatKkrw(WEI - 1n), "0.999999");
});

test("formatKkrw groups the integer part and keeps trailing zeros", () => {
  assert.equal(formatKkrw(1_234_567_890n * WEI), "1,234,567,890.000000");
  assert.equal(formatKkrw(1_000n * WEI + 5n * 10n ** 17n), "1,000.500000");
  assert.equal(formatKkrw(123n * WEI), "123.000000");
});

test("formatKkrw accepts decimal-string raw values (indexer amounts are strings)", () => {
  assert.equal(formatKkrw((250n * WEI).toString()), "250.000000");
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
  assert.equal(formatKkrw(-15n * 10n ** 17n), "-1.500000");
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
  for (const s of ["1,000,000.000000", "1.500000", "0.000001", "123.456789", "0.000000"]) {
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

// ============================ (3) ALLOWANCE LABEL ===========================

test("allowanceLabel: MaxUint256 reads Unlimited, ordinary values are formatted", () => {
  assert.equal(allowanceLabel(MAX_UINT256), "Unlimited");
  assert.equal(MAX_UINT256, (1n << 256n) - 1n);
  assert.equal(allowanceLabel(0n), "0.000000");
  assert.equal(allowanceLabel(1_000_000n * WEI), "1,000,000.000000");
  // one below MaxUint is NOT unlimited — it renders under the 6-decimal policy
  // (huge, but a finite grouped number — never the raw 78-digit integer).
  const nearMax = allowanceLabel(MAX_UINT256 - 1n);
  assert.notEqual(nearMax, "Unlimited");
  assert.match(nearMax, /^[\d,]+\.\d{6}$/);
});
