// Equality gate for the deployment-coupled chain facts (src/network.ts).
//
// Every constant in the network module describes the LIVE GIWA pool — a
// transcription slip breaks both apps against the live deployment and surfaces
// only at on-chain proof rejection. This suite convicts any slip in
// milliseconds instead:
//
//   1. Facts the deploy artifact carries (deploy/addresses.91342.json — the
//      canonical record, CLAUDE.md "live pool is canonical") are asserted
//      EQUAL to it field-for-field, so a redeploy that edits the JSON turns
//      this suite red until the module follows.
//   2. Facts the artifact does NOT carry (H, the gas floor, RPC/explorer
//      bases, the POOL_ABI_FRAGMENTS fragment strings) are pinned byte-for-byte to the
//      values previously hand-copied across apps/admin-web/src/lib/chain.ts,
//      apps/wallet-web/src/lib/metamask.ts, both app config.ts files, and
//      deploy/giwa_disburse256.ts — the copies this module replaced.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ARBITER_PUBKEY_X,
  ARBITER_PUBKEY_Y,
  B,
  CHAIN_ID,
  EXPLORER_BASE,
  GIWA_GAS_FLOOR_GWEI,
  H,
  POOL_ABI_FRAGMENTS,
  POOL_ADDRESS,
  RPC_URL,
  TOKEN_ADDRESS,
  explorerTxUrl,
} from "../src/network.js";

// packages/sdk/test -> repo root (tests run under tsx/node, not the browser).
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

interface Addresses {
  arbiterKeyX: string;
  arbiterKeyY: string;
  batchSize: number;
  chainId: number;
  pool: string;
  token: string;
}
const addr = JSON.parse(
  readFileSync(join(REPO_ROOT, "deploy", "addresses.91342.json"), "utf8"),
) as Addresses;

test("module facts equal deploy/addresses.91342.json field-for-field", () => {
  // JSON key -> module value, one row per fact the module owns. A redeploy
  // (new addresses.91342.json) fails here naming the exact stale field.
  const owned: Record<keyof Addresses, string | number> = {
    pool: POOL_ADDRESS,
    token: TOKEN_ADDRESS,
    chainId: CHAIN_ID,
    batchSize: B,
    arbiterKeyX: ARBITER_PUBKEY_X,
    arbiterKeyY: ARBITER_PUBKEY_Y,
  };
  for (const [key, moduleValue] of Object.entries(owned)) {
    assert.deepEqual(
      moduleValue,
      addr[key as keyof Addresses],
      `network.ts disagrees with addresses.91342.json on "${key}"`,
    );
  }
  // The tuple form both app configs consume is the same two scalars.
  assert.deepEqual([ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y], [addr.arbiterKeyX, addr.arbiterKeyY]);
});

test("facts outside the deploy artifact are pinned to the pre-module copies", () => {
  // SPEC §4 IMT height — was re-declared per app config.
  assert.equal(H, 32);
  // GIWA wants ~0.001 gwei; ethers' auto-estimate overpays ~1500x. 0.005 gwei
  // safe floor — was copied in chain.ts / metamask.ts / giwa_disburse256.ts.
  assert.equal(GIWA_GAS_FLOOR_GWEI, "0.005");
  // Chain endpoints — were copied in both app config.ts files.
  assert.equal(RPC_URL, "https://sepolia-rpc.giwa.io");
  assert.equal(EXPLORER_BASE, "https://sepolia-explorer.giwa.io");
});

test("POOL_ABI_FRAGMENTS fragments are byte-identical to the strings the apps shipped", () => {
  // Wallet fragments (apps/wallet-web/src/lib/metamask.ts): transfer/withdraw
  // take (a,b,c,pub) only — ciphertext rides in `pub` as circuit outputs.
  assert.equal(
    POOL_ABI_FRAGMENTS.transfer,
    "function transfer(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[36] pub)",
  );
  assert.equal(
    POOL_ABI_FRAGMENTS.withdraw,
    "function withdraw(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[25] pub)",
  );
  // Admin fragment (apps/admin-web/src/lib/chain.ts): §6b v2 enforced-length
  // disburse — receiverCiphertexts is the separate 2054-element calldata arg.
  assert.equal(
    POOL_ABI_FRAGMENTS.disburseWithCiphertexts,
    "function disburseWithCiphertexts(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[10] pub, uint256[] receiverCiphertexts)",
  );
  // Shared view fns.
  assert.equal(POOL_ABI_FRAGMENTS.root, "function root() view returns (uint256)");
  assert.equal(POOL_ABI_FRAGMENTS.nextLeafIndex, "function nextLeafIndex() view returns (uint256)");
  assert.equal(POOL_ABI_FRAGMENTS.B, "function B() view returns (uint256)");
});

test("explorerTxUrl builds the live explorer link (trailing slash tolerated)", () => {
  assert.equal(explorerTxUrl("0xabc"), "https://sepolia-explorer.giwa.io/tx/0xabc");
  // metamask.ts trimmed a trailing slash off the base; behavior preserved.
  assert.equal(explorerTxUrl("0xabc", "https://x.example/"), "https://x.example/tx/0xabc");
  assert.equal(explorerTxUrl("0xabc", "https://x.example"), "https://x.example/tx/0xabc");
});
