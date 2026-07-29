// runLogin's ordering contract, headless. The one being pinned hardest: the
// wallet is prompted onto GIWA BEFORE the first signature request — the typed
// data pins domain.chainId, wallets reject a v4 request whose domain chain
// differs from the active one, and a login must never fail with raw provider
// text where the add/switch prompt belongs. And the standing refusal rule:
// when the chain step (or any check) throws, NOTHING has been written.

import { test } from "node:test";
import assert from "node:assert/strict";

import { runLogin, type RunLoginDeps } from "../src/loginFlow.js";
import type { Connection } from "../src/connection.js";
import type { WalletIdentity } from "../src/derive.js";

const CONNECTION = { address: "0xabc", transport: "injected" } as unknown as Connection;
const IDENTITY = {
  compressedPubkey: "cpk1",
  keypair: { formattedPrivateKey: "priv" },
} as unknown as WalletIdentity;

function fakes(calls: string[], overrides: Partial<RunLoginDeps> = {}): RunLoginDeps {
  return {
    openConnection: async () => {
      calls.push("open");
      return CONNECTION;
    },
    ensureChain: async () => {
      calls.push("chain");
    },
    deriveIdentity: async () => {
      calls.push("derive");
      return IDENTITY;
    },
    obtainViewToken: async () => {
      calls.push("token");
      return { token: "t", exp: 9 };
    },
    loadKeyBinding: () => null,
    saveKeyBinding: () => {
      calls.push("saveBinding");
    },
    saveSession: () => {
      calls.push("saveSession");
    },
    ...overrides,
  };
}

test("login prompts the wallet onto GIWA before any signature is requested", async () => {
  const calls: string[] = [];
  await runLogin({ indexerUrl: "http://x" }, fakes(calls));
  assert.ok(
    calls.indexOf("chain") > calls.indexOf("open") && calls.indexOf("chain") < calls.indexOf("derive"),
    `ensureChain must run between connect and the signing derivation, got: ${calls.join(",")}`,
  );
});

test("a refused chain switch aborts the login with nothing written", async () => {
  const calls: string[] = [];
  const deps = fakes(calls, {
    ensureChain: async () => {
      throw new Error("Switch to GIWA Sepolia in your wallet to continue.");
    },
  });
  await assert.rejects(() => runLogin({ indexerUrl: "http://x" }, deps), /GIWA/);
  assert.ok(!calls.includes("derive"), "no signature may be requested on the wrong chain");
  assert.ok(!calls.includes("saveSession") && !calls.includes("saveBinding"), "refusals write nothing");
});

test("happy path returns the session and records the binding", async () => {
  const calls: string[] = [];
  const res = await runLogin({ indexerUrl: "http://x" }, fakes(calls));
  assert.equal(res.tokenless, false);
  assert.equal(res.session.token, "t");
  assert.deepEqual(
    calls.slice(-2),
    ["saveSession", "saveBinding"],
    "persists only after every check passed",
  );
});
