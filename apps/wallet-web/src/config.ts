// App-specific knobs only. The deployment-coupled chain facts (pool, token,
// chainId, RPC/explorer, arbiter public key, H/B, gas floor, ABI fragments)
// live in @bongtu/sdk/network — ONE home, equality-tested against
// deploy/addresses.91342.json — and are re-exposed here in the DEFAULTS shape
// the views consume. Everything is PUBLIC. The arbiter *public* key is the
// pool's stored authority pubkey — the wallet encrypts every transfer/withdraw
// authority envelope to it (non-repudiation on every op, SPEC §2 Q2), so it
// must ship in the client. No PRIVATE key ever lives in the public wallet: the
// user's bjj spending key is DERIVED from a MetaMask signature at runtime
// (src/lib/derive.ts) and never persisted.

import {
  ARBITER_PUBKEY_X,
  ARBITER_PUBKEY_Y,
  B,
  CHAIN_ID,
  EXPLORER_BASE,
  POOL_ADDRESS,
  RPC_URL,
  TOKEN_ADDRESS,
} from "@bongtu/sdk/network";

export const DEFAULTS = {
  chainId: CHAIN_ID,
  rpc: RPC_URL,
  explorer: EXPLORER_BASE,
  pool: POOL_ADDRESS,
  token: TOKEN_ADDRESS,
  batchSize: B,
  // The pool's stored arbiter PUBLIC key (addresses.91342.json arbiterKeyX/Y). The
  // transfer/withdraw circuits encrypt an authority envelope to this key; the
  // contract injects the SAME key from storage before verifying, so a mismatch fails.
  arbiterPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y] as [string, string],
  // KDF domain version (SPEC §6): part of the EIP-712 domain, so bumping it rotates
  // every derived key. Pinned per deployment; never silently changed.
  keyVersion: "1",
  // The arbiter-mode indexer for the signed `GET /notes` balance path (required —
  // the wallet has no fallback balance path; decision 2026-07-25, review #17b).
  indexerUrl: "http://localhost:8600",
  // Where the transfer/withdraw circuit assets (wasm + zkey) are served for browser
  // snarkjs proving. Static assets under the app, or a configured CDN/helper URL.
  // Files: `${circuitBaseUrl}/{transfer,withdraw}.wasm` and `.zkey`.
  circuitBaseUrl: "/circuits",
} as const;

export { H, B } from "@bongtu/sdk/network";
