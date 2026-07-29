// Gate for the console's Korean boundary (lib/errors.ts). Two rules are pinned:
//
//   - the failures a payroll operator actually hits are worded in Korean, keyed off
//     the SHARED structural classifier rather than off English text;
//   - the deposit field's amount errors are Korean and DISTINCT, driven through the
//     real parseKkrw — so a reword in @bongtu/client/money fails this gate instead
//     of silently collapsing every cause into one vague fallback.

import { test } from "node:test";
import assert from "node:assert/strict";

import { errorDetails, parseDepositAmount, payrollErrorMessage } from "../src/lib/errors.js";

const hasHangul = (s: string): boolean => /[가-힣]/.test(s);

// ---------------------------- wallet / RPC failures -------------------------------

test("the failures an operator hits are Korean", () => {
  const cases: [unknown, RegExp][] = [
    [Object.assign(new Error("User rejected the request"), { code: 4001 }), /서명을 거부/],
    [new Error("insufficient funds for gas"), /ETH가 부족/],
    [Object.assign(new Error("switch chain failed"), { name: "SwitchChainError" }), /네트워크/],
    [Object.assign(new Error("request timed out"), { name: "TimeoutError" }), /시간이 초과/],
    [Object.assign(new Error("Failed to fetch"), { name: "HttpRequestError" }), /연결/],
  ];
  for (const [thrown, expected] of cases) {
    assert.match(payrollErrorMessage(thrown), expected);
  }
});

test("a declined network switch is told apart from a failed one", () => {
  const declined = Object.assign(new Error("wallet_switchEthereumChain"), { code: 4001 });
  assert.match(payrollErrorMessage(declined), /거부/);
  assert.match(payrollErrorMessage(new Error("wallet_switchEthereumChain unavailable")), /전환하지 못했습니다/);
});

test("anything the classifier cannot name keeps the words it already has", () => {
  // A Korean engine error passes through unharmed (the run's own messages are
  // already in the console's voice) …
  assert.equal(payrollErrorMessage(new Error("잔고가 방금 바뀌었습니다.")), "잔고가 방금 바뀌었습니다.");
  // … and a precise English revert beats a vague Korean paraphrase of it.
  assert.match(payrollErrorMessage(new Error("execution reverted: InvalidProof")), /InvalidProof/);
});

test("the raw thrown value stays available for Copy details", () => {
  const details = errorDetails(new Error("execution reverted: InvalidProof"));
  assert.match(details, /InvalidProof/, "the engine's own line survives the translation");
});

// ---------------------------- the deposit amount field ----------------------------

test("every amount rejection is Korean, and each cause says something different", () => {
  const rejected = ["", "1,5", "abc", "1.1234567", "9".repeat(40)];
  const messages = rejected.map((input) => {
    const parsed = parseDepositAmount(input);
    assert.equal(parsed.ok, false, `${JSON.stringify(input)} must be rejected`);
    return parsed.ok ? "" : parsed.error;
  });
  for (const [i, message] of messages.entries()) {
    assert.ok(hasHangul(message), `${JSON.stringify(rejected[i])} -> ${message}`);
    assert.ok(!/[a-z]{4,}/i.test(message), `English leaked through: ${message}`);
  }
  assert.equal(new Set(messages).size, messages.length, "each cause keeps its own wording");
});

test("a good amount parses to the same wei parseKkrw gives", () => {
  const parsed = parseDepositAmount("1,000.5");
  assert.deepEqual(parsed, { ok: true, wei: 10005n * 10n ** 18n / 10n });
});
