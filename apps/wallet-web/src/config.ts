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

/**
 * Deployment posture from ENV, never copy checks: `VITE_TESTNET=false` at build time
 * flips every testnet-only affordance (faucet/mint UI, Testnet chips, mint onboarding
 * copy) off in one place. Default TRUE because every current deployment is GIWA
 * Sepolia. Pure so the default-true rule is testable under the node runner.
 */
export function testnetFromEnv(value: string | undefined): boolean {
  return (value ?? "true") !== "false";
}

export const DEFAULTS = {
  chainId: CHAIN_ID,
  // Testnet posture from ENV, never copy checks (see testnetFromEnv); default true
  // because every current deployment is GIWA Sepolia.
  testnet: testnetFromEnv(import.meta.env?.VITE_TESTNET),
  rpc: RPC_URL,
  explorer: EXPLORER_BASE,
  // The official GIWA testnet-ETH faucet (docs.giwa.io/en/get-started/faucets) —
  // linked from the zero-gas error so a stuck first-timer has a next step.
  gasFaucet: "https://faucet.giwa.io",
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
  // snarkjs proving. One source in every environment: the bongtu-circuits blob store
  // under the CIRCUITS_VERSION path — reached through this same-origin path by the
  // vercel.json rewrite in deployments and the vite dev proxy locally.
  // Files: `${circuitBaseUrl}/{transfer,withdraw}.wasm` and `.zkey`.
  circuitBaseUrl: "/circuits",
} as const;

// first 8 of sha256 over the FOUR keys the wallet proves against, concatenated in
// this documented order (the version bucket stores them all, so regenerating any one
// must change the version):
//   cat public/circuits/transfer.zkey circuits/out/transfer10.zkey public/circuits/withdraw.zkey circuits/out/deposit.zkey | sha256sum | cut -c1-8
// The proving-asset module keys its Cache Storage bucket on this
// ("bongtu-circuits-v<version>") and evicts any stale bucket, so a re-proven zkey forces
// a one-time re-download instead of serving a mismatched key from disk (a stale key fails
// on-chain verify with no self-heal). Bump this the moment ANY zkey changes on disk.
// A bump is live only with its two companions in the SAME change: upload the new
// assets (deploy/upload_circuits.sh — refuses a hash that doesn't match this pin)
// and point vercel.json's /circuits rewrite at the new circuits/<version>/ path.
export const CIRCUITS_VERSION = "2109f115";

// Exact byte sizes of the served proving assets — the download progress bar's
// denominator. Needed because the CDN strips/deflates Content-Length on some
// assets (br-compressed wasm), which would leave the bar indeterminate; these
// are the DECODED sizes, matching what the streaming reader counts. Re-pin
// alongside CIRCUITS_VERSION whenever a zkey/wasm changes:
//   stat -c "%n %s" public/circuits/*
/** The circuits with browser-served proving assets — one name per {wasm, zkey} pair
 *  under `circuitBaseUrl`, and the key every asset/download path is typed on. */
export type BrowserCircuit = "transfer" | "transfer10" | "withdraw" | "deposit";

export const CIRCUIT_ASSET_BYTES: Record<BrowserCircuit, { wasm: number; zkey: number }> = {
  transfer: { wasm: 3924469, zkey: 28903456 },
  // transfer10 is ~114 MB of zkey — 4x the 2x2 transfer — which is why the wallet
  // fetches it ONLY once note selection says a spend needs 3+ input notes, never on
  // screen open (sizes from circuits/out/, the same build the blob store serves).
  transfer10: { wasm: 4717238, zkey: 114422848 },
  withdraw: { wasm: 3881862, zkey: 24869572 },
  deposit: { wasm: 3364023, zkey: 6776800 },
};

export { H, B } from "@bongtu/core/network";
