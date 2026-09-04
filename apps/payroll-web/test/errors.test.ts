// Gate for the console's wording boundary (lib/errors.ts). Two rules are pinned:
//
//   - the failures a payroll operator actually hits are worded for the console,
//     keyed off the SHARED structural classifier rather than off matching text —
//     each verdict names its fix (switch network, check connection, retry);
//   - the deposit field's amount errors are DISTINCT per cause, driven through
//     the real parseKkrw — so a wording collapse in @bongtu/client/money fails
//     this gate instead of reaching the deposit field as one vague line.

import { test } from "node:test";
import assert from "node:assert/strict";

import { CHAIN_NAME, GAS_TOKEN_PHRASE } from "@bongtu/core/network";
import { errorDetails, parseDepositAmount, payrollErrorMessage } from "../src/lib/errors.js";

// ---------------------------- wallet / RPC failures -------------------------------

test("the failures an operator hits each name their fix", () => {
  const cases: [unknown, RegExp][] = [
    [Object.assign(new Error("User rejected the request"), { code: 4001 }), /rejected in your wallet/],
    [new Error("insufficient funds for gas"), new RegExp(`${GAS_TOKEN_PHRASE} to pay gas`)],
    [Object.assign(new Error("switch chain failed"), { name: "SwitchChainError" }), new RegExp(CHAIN_NAME)],
    [Object.assign(new Error("request timed out"), { name: "TimeoutError" }), /timed out/],
    [Object.assign(new Error("Failed to fetch"), { name: "HttpRequestError" }), /Check your connection/],
  ];
  for (const [thrown, expected] of cases) {
    assert.match(payrollErrorMessage(thrown), expected);
  }
});

test("a declined network switch is told apart from a failed one", () => {
  const declined = Object.assign(new Error("wallet_switchEthereumChain"), { code: 4001 });
  assert.match(payrollErrorMessage(declined), /rejected/);
  assert.match(payrollErrorMessage(new Error("wallet_switchEthereumChain unavailable")), /Could not switch/);
});

test("anything the classifier cannot name keeps the words it already has", () => {
  // The engine's own operator-worded lines pass through unharmed …
  assert.equal(
    payrollErrorMessage(new Error("Your balance just changed. Try again in a moment.")),
    "Your balance just changed. Try again in a moment.",
  );
  // … and a precise revert beats a vague paraphrase of it.
  assert.match(payrollErrorMessage(new Error("execution reverted: InvalidProof")), /InvalidProof/);
});

test("the raw thrown value stays available for Copy details", () => {
  const details = errorDetails(new Error("execution reverted: InvalidProof"));
  assert.match(details, /InvalidProof/, "the engine's own line survives the rewording");
});

// ---------------------------- the deposit amount field ----------------------------

test("every amount rejection says something different per cause", () => {
  const rejected = ["", "1,5", "abc", "1.1234567", "9".repeat(40)];
  const messages = rejected.map((input) => {
    const parsed = parseDepositAmount(input);
    assert.equal(parsed.ok, false, `${JSON.stringify(input)} must be rejected`);
    return parsed.ok ? "" : parsed.error;
  });
  for (const [i, message] of messages.entries()) {
    assert.ok(message.length > 0, `${JSON.stringify(rejected[i])} -> ${message}`);
  }
  assert.equal(new Set(messages).size, messages.length, "each cause keeps its own wording");
});

test("a good amount parses to the same wei parseKkrw gives", () => {
  const parsed = parseDepositAmount("1,000.5");
  assert.deepEqual(parsed, { ok: true, wei: 10005n * 10n ** 18n / 10n });
});
