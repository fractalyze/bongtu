// App-specific knobs only. The deployment-coupled chain facts (pool, token,
// chainId, RPC/explorer, arbiter public key, H/B, gas floor, ABI fragments)
// live in @bongtu/core/network — ONE home, equality-tested against
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
} from "@bongtu/core/network";

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
  // Default is the RELATIVE base `/indexer`, which the Vite proxy (vite.config
  // server+preview) forwards to the real indexer server-side. The relative base makes
  // every /notes,/history,/head,... call SAME-ORIGIN, so there is no CORS wall and a
  // port-forwarded remote dev box reaches the indexer with ONE tunnel (just the wallet
  // port). Set VITE_INDEXER_URL to an absolute URL to bypass the proxy and hit an
  // indexer directly. Runtime-overridable per session in the Settings screen too.
  // `import.meta.env` is a Vite build-time inject — undefined under the plain
  // node:test runner, so read it defensively (falls back to the relative default).
  indexerUrl: import.meta.env?.VITE_INDEXER_URL || "/indexer",
  // Where the transfer/withdraw circuit assets (wasm + zkey) are served for browser
  // snarkjs proving. Static assets under the app, or a configured CDN/helper URL.
  // Files: `${circuitBaseUrl}/{transfer,withdraw}.wasm` and `.zkey`.
  circuitBaseUrl: "/circuits",
} as const;

// first 8 of sha256(public/circuits/transfer.zkey || withdraw.zkey || deposit.zkey) —
// covers all THREE keys the wallet proves against, since the version bucket stores them
// all. Regenerate on any circuit change (bongtu regen recipe) so the browser cache
// auto-refetches. The proving-asset module keys its Cache Storage bucket on this
// ("bongtu-circuits-v<version>") and evicts any stale bucket, so a re-proven zkey forces
// a one-time re-download instead of serving a mismatched key from disk (a stale key fails
// on-chain verify with no self-heal). Bump this the moment ANY zkey changes on disk:
//   cat public/circuits/transfer.zkey public/circuits/withdraw.zkey circuits/out/deposit.zkey | sha256sum | cut -c1-8
export const CIRCUITS_VERSION = "ca05ab9f";

// Exact byte sizes of the served proving assets — the download progress bar's
// denominator. Needed because the CDN strips/deflates Content-Length on some
// assets (br-compressed wasm), which would leave the bar indeterminate; these
// are the DECODED sizes, matching what the streaming reader counts. Re-pin
// alongside CIRCUITS_VERSION whenever a zkey/wasm changes:
//   stat -c "%n %s" public/circuits/*
export const CIRCUIT_ASSET_BYTES: Record<"transfer" | "withdraw" | "deposit", { wasm: number; zkey: number }> = {
  transfer: { wasm: 3924403, zkey: 28903136 },
  withdraw: { wasm: 3881862, zkey: 24869572 },
  deposit: { wasm: 3364023, zkey: 6776800 },
};

export { H, B } from "@bongtu/core/network";
