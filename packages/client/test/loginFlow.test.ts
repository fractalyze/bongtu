// runLogin's ordering contract, headless. The one being pinned hardest: the
// wallet is prompted onto the live chain BEFORE the first signature request — the typed
// data pins domain.chainId, wallets reject a v4 request whose domain chain
// differs from the active one, and a login must never fail with raw provider
// text where the add/switch prompt belongs. And the standing refusal rule:
// when the chain step (or any check) throws, NOTHING has been written.

import { test } from "node:test";
import assert from "node:assert/strict";

import { CHAIN_NAME } from "@bongtu/core/network";

import { runLogin, type RunLoginDeps } from "../src/loginFlow.js";
import { chainSwitchMessage, type Connection } from "../src/connection.js";
import type { WalletIdentity } from "../src/derive.js";
import { KEY_CHANGED_MESSAGE } from "../src/loginGuard.js";
import { loadKeyBinding, saveKeyBinding, type StorageLike } from "../src/session.js";

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

test("login prompts the wallet onto the live chain before any signature is requested", async () => {
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
    // The text ensureChain actually surfaces for a declined EIP-3326 request
    // (connection.ts chainSwitchMessage) — not an invented string.
    ensureChain: async () => {
      throw new Error(chainSwitchMessage(Object.assign(new Error("user rejected"), { code: 4001 })));
    },
  });
  await assert.rejects(() => runLogin({ indexerUrl: "http://x" }, deps), new RegExp(CHAIN_NAME));
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

// --- the binding check across a deployment move ------------------------------------
// CHAIN_ID and POOL_ADDRESS are BOTH in the EIP-712 KDF domain, so when either moves
// every account legitimately derives a different key. Reading the pre-move binding
// here would fire KEY_CHANGED_MESSAGE — telling every returning user their wallet is
// broken, with no in-app way out (clearKeyBindings sits behind a Settings screen that
// needs a live session). session.ts scopes the storage key to the deployment so the
// real loader finds nothing; these two tests pin BOTH halves of that.

function memStorage(): StorageLike & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  };
}

/** runLogin over the REAL binding store, backed by `storage`. */
function overStorage(calls: string[], storage: StorageLike) {
  return fakes(calls, {
    loadKeyBinding: (eoa) => loadKeyBinding(eoa, storage),
    saveKeyBinding: (eoa, pubkey) => {
      calls.push("saveBinding");
      saveKeyBinding(eoa, pubkey, storage);
    },
  });
}

test("a binding left by ANOTHER deployment does not refuse the login", async () => {
  const storage = memStorage();
  // What the device kept from the pre-move deployment (chain 91342, its own pool):
  // a real binding for this same account, naming a key this build cannot derive.
  storage.map.set(
    "bongtu.keybinding.91342:0x22a2f38a24a2647e430dc28a5154d390f93ccf7b",
    JSON.stringify({ "0xabc": "cpk-from-the-old-deployment" }),
  );

  const calls: string[] = [];
  const res = await runLogin({ indexerUrl: "http://x" }, overStorage(calls, storage));
  assert.equal(res.session.compressedPubkey, "cpk1", "the login completes on the new identity");
  assert.equal(loadKeyBinding("0xabc", storage), "cpk1", "and this deployment records its own binding");
});

test("but a DIFFERENT key under THIS deployment still refuses — the guard is intact", async () => {
  const storage = memStorage();
  saveKeyBinding("0xabc", "a-different-key", storage);

  const calls: string[] = [];
  await assert.rejects(
    () => runLogin({ indexerUrl: "http://x" }, overStorage(calls, storage)),
    new RegExp(KEY_CHANGED_MESSAGE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
  );
  assert.ok(!calls.includes("saveSession") && !calls.includes("saveBinding"), "refusals write nothing");
  assert.equal(loadKeyBinding("0xabc", storage), "a-different-key", "the remembered key is not overwritten");
});
