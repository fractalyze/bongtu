// Gate for the wallet's wording boundary (lib/errors.ts) — the adoption the
// sibling apps already had (issue #45): every wallet/RPC failure routes through
// the SHARED structural classifier and the exhaustive copy table, never raw
// provider text, and each verdict a user actually hits names its fix.

import { test } from "node:test";
import assert from "node:assert/strict";

import { CHAIN_NAME, GAS_TOKEN_PHRASE } from "@bongtu/core/network";
import { TREASURY_FAILURE_COPY, treasuryErrorMessage } from "../src/lib/errors.js";
import type { ChainFailure } from "@bongtu/core/errors";

test("the failures a user hits each name their fix", () => {
  const cases: [unknown, RegExp][] = [
    [Object.assign(new Error("User rejected the request"), { code: 4001 }), /rejected in your wallet/],
    [new Error("insufficient funds for gas"), new RegExp(`${GAS_TOKEN_PHRASE} to pay gas`)],
    [Object.assign(new Error("switch chain failed"), { name: "SwitchChainError" }), new RegExp(CHAIN_NAME)],
    [Object.assign(new Error("request timed out"), { name: "TimeoutError" }), /timed out/],
    [Object.assign(new Error("Failed to fetch"), { name: "HttpRequestError" }), /Check your connection/],
  ];
  for (const [thrown, expected] of cases) {
    assert.match(treasuryErrorMessage(thrown), expected);
  }
});

test("a declined network switch is told apart from a failed one", () => {
  const declined = Object.assign(new Error("wallet_switchEthereumChain"), { code: 4001 });
  assert.match(treasuryErrorMessage(declined), /rejected/);
  assert.match(treasuryErrorMessage(new Error("wallet_switchEthereumChain unavailable")), /Could not switch/);
});

test("anything the classifier cannot name keeps the words it already has", () => {
  // The engine's own lines pass through unharmed (the flows' money-state
  // reassurance rides them) ...
  assert.equal(
    treasuryErrorMessage(new Error("Your balance just changed. Try again in a moment.")),
    "Your balance just changed. Try again in a moment.",
  );
  // ... and a precise revert beats a vague paraphrase of it.
  assert.match(treasuryErrorMessage(new Error("execution reverted: InvalidProof")), /InvalidProof/);
});

test("the wallet copy table covers every ChainFailure kind, each with words", () => {
  assert.deepEqual(
    Object.keys(TREASURY_FAILURE_COPY).sort(),
    ["chain_switch", "insufficient_gas", "other", "timeout", "transport", "user_rejected"],
    "a kind added to the classifier must get a wording decision here, not a fall-through",
  );
  for (const [kind, words] of Object.entries(TREASURY_FAILURE_COPY)) {
    for (const rejected of [false, true]) {
      const failure = { kind, rejected, text: "engine line" } as unknown as ChainFailure;
      const message = (words as (f: ChainFailure, e: unknown) => string)(failure, new Error("engine line"));
      assert.ok(message.length > 0, `${kind} (rejected=${rejected}) must map to words`);
    }
  }
  const declined = { kind: "chain_switch", rejected: true, text: null } as unknown as ChainFailure;
  assert.match(TREASURY_FAILURE_COPY.chain_switch(declined as never, declined), /^Network switch rejected in your wallet/);
});
