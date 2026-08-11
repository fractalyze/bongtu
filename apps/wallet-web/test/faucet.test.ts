// Headless gates for the dev faucet + the deposit balance precheck (SPEC §7). The tx
// edges themselves (MockERC20.mint, ERC-20 approve, snarkjs) are ethers/browser-bound
// and out of scope; what IS pure and security/UX-critical is covered here:
//
//   (1) FAUCET AMOUNT — 1,000,000 kKRW at the token's 18 decimals (raw 10^24 wei), so
//       MetaMask and the wallet's 6-decimal display both show "1,000,000" after a mint.
//       (The old zero-balance gate — shouldOfferFaucet — was deleted: the faucet is
//       always offered now, so there is no decision left to test.)
//   (2) BALANCE PRECHECK — assertDepositAffordable throws exactly when V > balance.
//   (3) FLOW GUARD — runDeposit rejects a deposit that exceeds the public balance
//       WITHOUT emitting an approve tx (and never reaching the proof), so a doomed
//       deposit fails fast; the happy path still threads approve → prove → submit.
//   (4) TESTNET POSTURE — the ENV-derived flag every testnet-only affordance
//       (faucet UI included) gates on: default true, only literal "false" disables.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { Calldata } from "@bongtu/core/proving";
import { DEFAULTS, testnetFromEnv } from "../src/config.js";
import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { FAUCET_AMOUNT } from "../src/lib/faucet.js";
import { assertDepositAffordable } from "@bongtu/client/deposit";
import { KeyCache } from "@bongtu/client/keyCache";
import {
  runDeposit,
  DEPOSIT_FAILURE_REASSURANCE,
  type DepositContext,
  type DepositIo,
  type RunDepositDeps,
} from "@bongtu/client/depositFlow";

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";

// The identity the fixed signature derives — the session pubkey every context below
// claims, so the flow's account-binding check passes unless a test breaks it.
const SESSION_PUBKEY = deriveIdentityFromSignature(SIG).compressedPubkey;

const ACCOUNT = "0x0000000000000000000000000000000000000001";

// A stand-in connection: runDeposit only reads `.address` here (the I/O it would perform
// on `.provider`/`.signer` is injected as fakes), so an empty provider/signer is fine.
function fakeContext(sessionPubkey: string = SESSION_PUBKEY): DepositContext {
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    connection: { address: ACCOUNT, provider: {}, signer: {} } as any,
    pool: "0x0000000000000000000000000000000000000b0b",
    token: "0x0000000000000000000000000000000000000c0c",
    explorer: "https://x",
    sessionPubkey,
  };
}

// A locked wallet whose unlock returns the fixed-signature identity instead of popping
// a real MetaMask signature. `onDerive` counts the popups the user would have seen.
function fakeKeyCache(onDerive: () => void = () => {}): KeyCache {
  return new KeyCache({
    derive: async () => {
      onDerive();
      return deriveIdentityFromSignature(SIG);
    },
    currentAccount: async () => ACCOUNT,
    arm: () => () => {},
  });
}

// The MetaMask edges every flow test injects: chain alignment is a no-op and the
// spending key comes from a fake lock (keyCache.ts).
function fakeWalletDeps(): Pick<RunDepositDeps, "ensureChain" | "assertPoolKemEpoch" | "keyCache"> {
  return {
    ensureChain: async () => {},
    assertPoolKemEpoch: async () => {},
    keyCache: fakeKeyCache(),
  };
}

test("FAUCET_AMOUNT is 1,000,000 kKRW in raw wei (10^24)", () => {
  assert.equal(typeof FAUCET_AMOUNT, "bigint");
  assert.equal(FAUCET_AMOUNT, 1_000_000n * 10n ** 18n);
  assert.equal(FAUCET_AMOUNT, 10n ** 24n);
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

test("runDeposit rejects V > balance BEFORE approving, key-deriving, or proving", async () => {
  let approveCalls = 0;
  let proveCalls = 0;
  let deriveCalls = 0;
  const deps: DepositIo = {
    ...fakeWalletDeps(),
    keyCache: fakeKeyCache(() => deriveCalls++),
    readTokenState: async () => ({ balance: 100n, allowance: 0n }),
    approveToken: async () => {
      approveCalls++;
      return "0xapprove";
    },
    prove: async () => {
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
  assert.equal(deriveCalls, 0, "no key derivation (signature popup) for a doomed deposit");
});

test("runDeposit happy path threads kem-guard → unlock → approve → prove → submit when affordable", async () => {
  let approveCalls = 0;
  let proveCalls = 0;
  let kemGuardCalls = 0;
  let deriveCalls = 0;
  const stages: string[] = [];
  const deps: DepositIo = {
    ...fakeWalletDeps(),
    keyCache: fakeKeyCache(() => {
      // The unlock signature appears only after the kem guard, and before any tx —
      // an account switch must not cost the user an approve.
      assert.equal(kemGuardCalls, 1, "the wallet unlocks AFTER the kem guard");
      assert.equal(approveCalls, 0, "the wallet unlocks BEFORE the approve tx");
      assert.equal(proveCalls, 0, "the wallet unlocks BEFORE the proof");
      deriveCalls++;
    }),
    readTokenState: async () => ({ balance: 1_000n, allowance: 0n }), // allowance < V => approve
    approveToken: async () => {
      approveCalls++;
      return "0xapprove";
    },
    assertPoolKemEpoch: async () => {
      // The on-chain key check must precede encapsulation/proving (design §4/§5).
      assert.equal(proveCalls, 0, "kem guard runs BEFORE the proof");
      kemGuardCalls++;
    },
    prove: async () => {
      proveCalls++;
      return DUMMY_CALLDATA;
    },
    submitDeposit: async () => ({ txHash: "0xdeposit", explorerUrl: "https://x/tx/0xdeposit" }),
  };

  const out = await runDeposit(fakeContext(), { amount: "500" }, (s) => stages.push(s), deps);
  assert.equal(approveCalls, 1, "an exact-V approve is sent when allowance < V");
  assert.equal(kemGuardCalls, 1, "the pool's arbiter KEM key hash was checked");
  assert.equal(deriveCalls, 1, "exactly ONE signature to unlock a locked wallet");
  assert.equal(proveCalls, 1);
  assert.equal(out.approved, true);
  assert.equal(out.amount, "500");
  assert.equal(out.txHash, "0xdeposit");
  assert.deepEqual(stages, ["unlock", "approve", "prove", "submit"]);
});

test("runDeposit refuses when the pool's KEM epoch rejects this build's key", async () => {
  let proveCalls = 0;
  const deps: DepositIo = {
    ...fakeWalletDeps(),
    keyCache: fakeKeyCache(() => {
      throw new Error("no key derivation may happen against an unverified key");
    }),
    readTokenState: async () => ({ balance: 1_000n, allowance: 500n }),
    assertPoolKemEpoch: async () => {
      throw new Error("on-chain arbiter KEM key hash 0x11 does not match this build's ARBITER_KEM_PK");
    },
    prove: async () => {
      proveCalls++;
      return DUMMY_CALLDATA;
    },
    submitDeposit: async () => {
      throw new Error("submit must not be reached when the kem guard refuses");
    },
  };
  await assert.rejects(
    runDeposit(fakeContext(), { amount: "500" }, () => {}, deps),
    /does not match this build's ARBITER_KEM_PK/,
  );
  assert.equal(proveCalls, 0, "no proof may be generated against an unverified key");
});

// ============================ (4) TESTNET POSTURE ===========================
// Every testnet-only affordance (this faucet's UI, Testnet chips, mint onboarding
// copy) gates on DEFAULTS.testnet, which comes from ENV via testnetFromEnv —
// never a copy check. Locked rule: default TRUE (every current deployment is a
// testnet); ONLY the literal "false" turns it off.

test("testnetFromEnv: default-true, only literal 'false' disables", () => {
  assert.equal(testnetFromEnv(undefined), true); // unset env (and the node runner)
  assert.equal(testnetFromEnv("true"), true);
  assert.equal(testnetFromEnv(""), true); // empty var is not an opt-out
  assert.equal(testnetFromEnv("0"), true); // no truthiness guessing — literal match only
  assert.equal(testnetFromEnv("false"), false);
});

test("DEFAULTS.testnet is true where import.meta.env is absent (node runner)", () => {
  assert.equal(DEFAULTS.testnet, true);
});

// ============================ (5) MONEY-STATE LINE ==========================
// The error-surface standard (.dev/error-surface-design.md): a money-touching
// failure carries the money-state line ONCE something partial has landed. For a
// deposit that is the approve tx: fail after it and the message must say the
// tokens never moved and the approval is reused; fail before it and the line
// must NOT appear (nothing partial can exist — it would only confuse).

test("a deposit failing AFTER its approve landed carries the money-state line", async () => {
  const deps: DepositIo = {
    ...fakeWalletDeps(),
    readTokenState: async () => ({ balance: 1_000n, allowance: 0n }), // approve needed
    approveToken: async () => "0xapprove",
    prove: async () => {
      throw new Error("proof worker crashed");
    },
    submitDeposit: async () => {
      throw new Error("unreachable");
    },
  };
  await assert.rejects(runDeposit(fakeContext(), { amount: "500" }, () => {}, deps), (e: Error) => {
    assert.match(e.message, /proof worker crashed/, "the specific cause leads");
    assert.ok(e.message.endsWith(DEPOSIT_FAILURE_REASSURANCE), "the money-state line closes it");
    return true;
  });
});

test("a deposit failing with NO approve landed stays a plain failure (no reassurance)", async () => {
  const deps: DepositIo = {
    ...fakeWalletDeps(),
    readTokenState: async () => ({ balance: 1_000n, allowance: 10_000n }), // approve skipped
    approveToken: async () => {
      throw new Error("approve must not run when the allowance covers V");
    },
    prove: async () => {
      throw new Error("proof worker crashed");
    },
    submitDeposit: async () => {
      throw new Error("unreachable");
    },
  };
  await assert.rejects(runDeposit(fakeContext(), { amount: "500" }, () => {}, deps), (e: Error) => {
    assert.match(e.message, /proof worker crashed/);
    assert.ok(!e.message.includes(DEPOSIT_FAILURE_REASSURANCE), "single-tx failure carries no line");
    return true;
  });
});
