// App-specific knobs only. The deployment-coupled chain facts (pool, token,
// chainId, RPC/explorer, gas faucet) live in @bongtu/core/network — ONE home,
// equality-tested against the deploy record — and are re-exposed here in the
// DEFAULTS shape the views consume.
//
// This is the CONSUMER wallet (issue #13), and two wallet-web knobs are ABSENT
// by design, not by omission:
//   - no discovery-mode knob: self-scan IS the product — every balance and
//     activity fact comes from scanning the public feed with the wallet's own
//     keys, so there is no second engine to select;
//   - no institutional authority key of any kind: consumer outputs seal to
//     each RECIPIENT's registered triple (docs/consumer.md), so no authority
//     public key belongs in this bundle — a test convicts one reappearing.
// No PRIVATE key ever lives here either: the user's bjj spending key is
// DERIVED from a wallet signature at runtime (@bongtu/client/derive) and never
// persisted.

import {
  CHAIN_ID,
  CHAIN_NAME,
  EXPLORER_BASE,
  GAS_FAUCET_URL,
  POOL_ADDRESS,
  RPC_URL,
  TOKEN_ADDRESS,
} from "@bongtu/core/network";

/**
 * Deployment posture from ENV, never copy checks: `VITE_TESTNET=false` at build time
 * flips every testnet-only affordance (faucet/mint UI, Testnet chips) off in one
 * place. Default TRUE because every current deployment is a testnet. Pure so the
 * default-true rule is testable under the node runner.
 */
export function testnetFromEnv(value: string | undefined): boolean {
  return (value ?? "true") !== "false";
}

export const DEFAULTS = {
  chainId: CHAIN_ID,
  // The chain's display name, for the screens that show which network this is.
  chainName: CHAIN_NAME,
  // Testnet posture from ENV, never copy checks (see testnetFromEnv).
  testnet: testnetFromEnv(import.meta.env?.VITE_TESTNET),
  rpc: RPC_URL,
  explorer: EXPLORER_BASE,
  // The chain's official testnet-gas faucet (@bongtu/core/network, one home) —
  // linked from the zero-gas error so a stuck first-timer has a next step.
  gasFaucet: GAS_FAUCET_URL,
  pool: POOL_ADDRESS,
  token: TOKEN_ADDRESS,
  // The indexer whose PUBLIC endpoints (/events, /nullifiers, /head, /path,
  // /names) feed the self-scan and pay-by-name. Default is the RELATIVE base
  // `/indexer`, which the Vite proxy (vite.config server+preview) forwards to the
  // real indexer server-side — every read SAME-ORIGIN, so there is no CORS wall
  // and a port-forwarded remote dev box reaches the indexer with ONE tunnel. Set
  // VITE_INDEXER_URL to an absolute URL to bypass the proxy. `import.meta.env` is
  // a Vite build-time inject — undefined under the plain node:test runner, so read
  // it defensively (falls back to the relative default). In deployments the
  // vercel.json rewrite owns this path, and MUST target a PUBLIC-mode instance
  // (ops task on issue #13).
  indexerUrl: import.meta.env?.VITE_INDEXER_URL || "/indexer",
  // Where the consumer circuit assets (wasm + zkey) are served for browser snarkjs
  // proving. One source in every environment: the bongtu-circuits blob store under
  // the CIRCUITS_VERSION path — reached through this same-origin path by the
  // vercel.json rewrite in deployments and the vite dev proxy locally.
  // Files: `${circuitBaseUrl}/<circuit>.wasm` and `.zkey`.
  circuitBaseUrl: "/circuits",
} as const;

// PLACEHOLDER PIN — S7 is the uploader. Structured exactly like wallet-web's
// CIRCUITS_VERSION so S7 only edits VALUES, never shape: first 8 of sha256 over the
// FOUR consumer zkeys, concatenated in this documented order (the version bucket
// stores them all, so regenerating any one must change the version):
//   cat circuits/out/depositPriv.zkey circuits/out/transferPriv.zkey \
//       circuits/out/transfer10x2Priv.zkey circuits/out/withdrawPriv.zkey | sha256sum | cut -c1-8
// The proving-asset module keys its Cache Storage bucket on this
// ("bongtu-circuits-v<version>") and evicts any stale bucket, so a re-proven zkey
// forces a one-time re-download instead of serving a mismatched key from disk.
// A bump is live only with its two companions in the SAME change: upload the new
// assets to the blob store and point vercel.json's /circuits rewrite at the new
// circuits/<version>/ path. The all-zero placeholder cannot collide with a real
// hash pin, and a fetch against it 404s loudly instead of serving another app's
// bucket — S7 replaces it when it uploads the consumer set.
export const CIRCUITS_VERSION = "00000000";

/** The circuits with browser-served proving assets — one name per {wasm, zkey}
 *  pair under `circuitBaseUrl`, and the key every asset/download path is typed
 *  on. Exactly the P2P 4-op consumer family registered on the live pool
 *  (@bongtu/core/network CONSUMER_MODULES): nothing else is provable from this
 *  bundle. */
export type BrowserCircuit = "depositPriv" | "transferPriv" | "transfer10x2Priv" | "withdrawPriv";

// Exact byte sizes of the served proving assets — the download progress bar's
// denominator. Needed because the CDN strips/deflates Content-Length on some
// assets (br-compressed wasm), which would leave the bar indeterminate; these
// are the DECODED sizes, matching what the streaming reader counts. Sizes are
// stat'ed from circuits/out/ — the same build S7 uploads; re-pin alongside
// CIRCUITS_VERSION whenever a zkey/wasm changes:
//   stat -c "%n %s" circuits/out/*Priv_js/*.wasm circuits/out/*Priv.zkey
export const CIRCUIT_ASSET_BYTES: Record<BrowserCircuit, { wasm: number; zkey: number }> = {
  depositPriv: { wasm: 3396815, zkey: 10430360 },
  transferPriv: { wasm: 3911495, zkey: 27476696 },
  // transfer10x2Priv is ~92 MB of zkey — which is why the wallet fetches it ONLY
  // once note selection says a spend needs 3+ input notes, never on screen open.
  transfer10x2Priv: { wasm: 4491485, zkey: 92261240 },
  withdrawPriv: { wasm: 3884065, zkey: 24306492 },
};
