// Headless gates for the dev faucet + the deposit balance precheck (SPEC §7). The tx
// edges themselves (MockERC20.mint, ERC-20 approve, snarkjs) are ethers/browser-bound
// and out of scope; what IS pure and security/UX-critical is covered here:
//
//   (1) FAUCET DECISION — shouldOfferFaucet is true iff the public kKRW balance is 0
//       (a fresh wallet), and FAUCET_AMOUNT is a positive bigint comfortably above a
//       typical hand-typed deposit (so one tap funds many test deposits).
//   (2) BALANCE PRECHECK — assertDepositAffordable throws exactly when V > balance.
//   (3) FLOW GUARD — runDeposit rejects a deposit that exceeds the public balance
//       WITHOUT emitting an approve tx (and never reaching the proof), so a doomed
//       deposit fails fast; the happy path still threads approve → prove → submit.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { Calldata } from "@bongtu/core/proving";
import { deriveIdentityFromSignature } from "../src/lib/derive.js";
import { FAUCET_AMOUNT, shouldOfferFaucet } from "../src/lib/faucet.js";
import { assertDepositAffordable } from "../src/lib/deposit.js";
import {
  runDeposit,
  type DepositContext,
  type RunDepositDeps,
} from "../src/lib/depositFlow.js";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";

// A stand-in connection: runDeposit only reads `.address` here (the I/O it would perform
// on `.provider`/`.signer` is injected as fakes), so an empty provider/signer is fine.
function fakeContext(): DepositContext {
  return {
    identity: deriveIdentityFromSignature(SIG),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: "0x0000000000000000000000000000000000000001", provider: {}, signer: {} } as any,
  };
}

// ============================ (1) FAUCET DECISION ============================

test("shouldOfferFaucet is true only for a zero public balance", () => {
  assert.equal(shouldOfferFaucet(0n), true);
  assert.equal(shouldOfferFaucet(1n), false);
  assert.equal(shouldOfferFaucet(1_000n), false);
  assert.equal(shouldOfferFaucet(FAUCET_AMOUNT), false);
});

test("FAUCET_AMOUNT is a positive bigint comfortably above a typical small deposit", () => {
  assert.equal(typeof FAUCET_AMOUNT, "bigint");
  assert.ok(FAUCET_AMOUNT > 0n, "faucet amount must be positive");
  // a hand-typed test deposit is small (hundreds/thousands of raw units); one faucet tap
  // must cover many of them without re-minting.
  assert.ok(FAUCET_AMOUNT >= 100_000n, "faucet amount should be generous vs a typical deposit");
});

// ============================ (2) BALANCE PRECHECK ==========================

test("assertDepositAffordable throws exactly when V exceeds balance", () => {
  assert.doesNotThrow(() => assertDepositAffordable(500n, 500n)); // exactly affordable
  assert.doesNotThrow(() => assertDepositAffordable(1n, 1_000n));
  assert.throws(() => assertDepositAffordable(501n, 500n), /insufficient kKRW balance/i);
  assert.throws(() => assertDepositAffordable(1_000n, 0n), /insufficient kKRW balance/i);
});

// ============================ (3) FLOW GUARD ================================

const DUMMY_CALLDATA: Calldata = {
  a: ["0", "0"],
  b: [["0", "0"], ["0", "0"]],
  c: ["0", "0"],
  pub: [],
};

test("runDeposit rejects V > balance BEFORE approving or proving", async () => {
  let approveCalls = 0;
  let proveCalls = 0;
  const deps: Partial<RunDepositDeps> = {
    readTokenState: async () => ({ balance: 100n, allowance: 0n }),
    approveToken: async () => {
      approveCalls++;
      return "0xapprove";
    },
    proveInBrowser: async () => {
      proveCalls++;
      return DUMMY_CALLDATA;
    },
    submitDeposit: async () => {
      throw new Error("submit must not be reached on an unaffordable deposit");
    },
  };

  await assert.rejects(
    runDeposit(fakeContext(), { amount: "500" }, () => {}, deps),
    /insufficient kKRW balance/i,
  );
  assert.equal(approveCalls, 0, "no approve tx may be emitted for a doomed deposit");
  assert.equal(proveCalls, 0, "no proof may be generated for a doomed deposit");
});

test("runDeposit happy path threads approve → prove → submit when affordable", async () => {
  let approveCalls = 0;
  let proveCalls = 0;
  const stages: string[] = [];
  const deps: Partial<RunDepositDeps> = {
    readTokenState: async () => ({ balance: 1_000n, allowance: 0n }), // allowance < V => approve
    approveToken: async () => {
      approveCalls++;
      return "0xapprove";
    },
    proveInBrowser: async () => {
      proveCalls++;
      return DUMMY_CALLDATA;
    },
    submitDeposit: async () => ({ txHash: "0xdeposit", explorerUrl: "https://x/tx/0xdeposit" }),
  };

  const out = await runDeposit(fakeContext(), { amount: "500" }, (s) => stages.push(s), deps);
  assert.equal(approveCalls, 1, "an exact-V approve is sent when allowance < V");
  assert.equal(proveCalls, 1);
  assert.equal(out.approved, true);
  assert.equal(out.amount, "500");
  assert.equal(out.txHash, "0xdeposit");
  assert.deepEqual(stages, ["approve", "prove", "submit"]);
});
