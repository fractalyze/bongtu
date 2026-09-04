// Gate for createKeyCache — the ONE sanctioned app construction of the lock.
// The structural guarantee lives in its wiring, not in KeyCache (whose own state
// machine gates through the deps seam in keyCache.test.ts): both apps must end up
// deriving under the deployment's KDF config, with the wallet edge's live-account
// read as the session check. A wiring slip there would surface only manually, in
// both apps at once — so the wiring is proven here against the REAL derivation
// over a mock wallet (the deriveDeterminism.test.ts seam: the fake models the
// WALLET, everything in between is code under test).

import { test } from "node:test";
import assert from "node:assert/strict";

import { createWalletClient, custom } from "viem";
import { liveChain } from "../src/chain.js";
import type { Connection } from "../src/connection.js";
import { ACCOUNT_MISMATCH_MESSAGE, KEY_DERIVATION, deriveTransientIdentity } from "../src/identity.js";
import { createKeyCache } from "../src/keyCache.js";

const ACCOUNT = "0x1111111111111111111111111111111111111111";
const FIXED_SIG = ("0x" + "42".repeat(64) + "1b") as `0x${string}`;

function mockConnection(): Connection {
  const provider = {
    async request({ method }: { method: string; params?: unknown[] }): Promise<unknown> {
      if (method === "eth_signTypedData_v4") return FIXED_SIG;
      if (method === "eth_chainId") return "0x" + liveChain.id.toString(16);
      throw new Error(`unexpected RPC ${method}`);
    },
  };
  return {
    address: ACCOUNT,
    walletClient: createWalletClient({ account: ACCOUNT, chain: liveChain, transport: custom(provider) }),
    publicClient: {} as Connection["publicClient"],
    injected: provider,
    transport: "injected",
  };
}

test("createKeyCache derives under the deployment's KDF config", async () => {
  const connection = mockConnection();
  const expected = await deriveTransientIdentity(connection, KEY_DERIVATION);
  const cache = createKeyCache({ currentAccount: async () => ACCOUNT });
  const unlocked = await cache.unlock(connection, expected.compressedPubkey);
  assert.equal(unlocked.compressedPubkey, expected.compressedPubkey, "same KDF config ⇒ same identity");
});

test("createKeyCache re-checks the edge's LIVE account before reusing a held key", async () => {
  // A fresh unlock cannot detect the mismatch (the derived key is the evidence,
  // checked against the session pubkey); the edge read guards the CACHED key —
  // so the wiring is proven by unlocking, switching the live account, and
  // watching the reuse path refuse without a popup.
  const connection = mockConnection();
  const expected = await deriveTransientIdentity(connection, KEY_DERIVATION);
  const live = { account: ACCOUNT };
  const cache = createKeyCache({ currentAccount: async () => live.account });
  await cache.unlock(connection, expected.compressedPubkey);
  live.account = "0x" + "22".repeat(20);
  await assert.rejects(
    cache.unlock(connection, expected.compressedPubkey),
    (e: unknown) => e instanceof Error && e.message === ACCOUNT_MISMATCH_MESSAGE,
    "a mid-session account switch must refuse the held key through the edge's live read",
  );
});
