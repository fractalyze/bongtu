// App-specific knobs only. The deployment-coupled chain facts (pool, token,
// chainId, RPC/explorer, arbiter public key, H/B, gas floor, ABI fragments)
// live in @bongtu/core/network — ONE home, equality-tested against the deploy
// record — and are re-exposed here in the DEFAULTS shape
// the views consume. Everything is PUBLIC. The arbiter *public* key is the
// pool's stored authority pubkey — the wallet encrypts every transfer/withdraw
// authority envelope to it (non-repudiation on every op, SPEC §2 Q2), so it
// must ship in the client. No PRIVATE key ever lives in the public wallet: the
// user's bjj spending key is DERIVED from a MetaMask signature at runtime
// (@bongtu/client/derive) and never persisted.

import {
  ARBITER_PUBKEY_X,
  ARBITER_PUBKEY_Y,
  B,
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
 * flips every testnet-only affordance (faucet/mint UI, Testnet chips, mint onboarding
 * copy) off in one place. Default TRUE because every current deployment is a
 * testnet. Pure so the default-true rule is testable under the node runner.
 */
export function testnetFromEnv(value: string | undefined): boolean {
  return (value ?? "true") !== "false";
}

export const DEFAULTS = {
  chainId: CHAIN_ID,
  // Testnet posture from ENV, never copy checks (see testnetFromEnv); default true
  // because every current deployment is a testnet.
  testnet: testnetFromEnv(import.meta.env?.VITE_TESTNET),
  rpc: RPC_URL,
  explorer: EXPLORER_BASE,
  // The chain's official testnet-ETH faucet (@bongtu/core/network, one home) —
  // linked from the zero-gas error so a stuck first-timer has a next step.
  gasFaucet: GAS_FAUCET_URL,
  // The chain's display name, for the screens that show which network this is.
  chainName: CHAIN_NAME,
  pool: POOL_ADDRESS,
  token: TOKEN_ADDRESS,
  batchSize: B,
  // The pool's stored arbiter PUBLIC key (the record's arbiterKeyX/Y). The
  // transfer/withdraw circuits encrypt an authority envelope to this key; the
  // contract injects the SAME key from storage before verifying, so a mismatch fails.
  arbiterPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y] as [string, string],
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
  // The gas-sponsoring withdraw relayer (apps/relayer): set => the withdraw leg
  // submits through it (no gas popup — the payout is proof-bound, pub[26], so
  // the relayer cannot redirect it); EMPTY => self-submit, the pre-relayer
  // behavior. Dev gets the RELATIVE `/relayer` (Vite proxy → localhost:8700,
  // the same same-origin story as indexerUrl above); every other environment
  // defaults EMPTY because vercel.json has no /relayer rewrite yet — keep it
  // empty until that rewrite ships or deployments would POST into a 404.
  // VITE_RELAYER_URL overrides either way (absolute URL bypasses the proxy).
  relayerUrl: import.meta.env?.VITE_RELAYER_URL || (import.meta.env?.DEV ? "/relayer" : ""),
  // Where the transfer/withdraw circuit assets (wasm + zkey) are served for browser
  // snarkjs proving. One source in every environment: the bongtu-circuits blob store
  // under the CIRCUITS_VERSION path — reached through this same-origin path by the
  // vercel.json rewrite in deployments and the vite dev proxy locally.
  // Files: `${circuitBaseUrl}/{transfer,withdraw}.wasm` and `.zkey`.
  circuitBaseUrl: "/circuits",
} as const;

// The EIP-712 KDF domain facts this deployment derives every spending key under
// are NOT app config anymore: they live in @bongtu/client/identity KEY_DERIVATION
// (built from the sdk deployment facts), so wallet-web and payroll-web deriving
// the same key for the same account holds by construction. The two derivation
// call sites (login deps in App.tsx, the lock's lazy re-derive in lib/keyCache.ts)
// import it from there.

// first 8 of sha256 over the FOUR keys the wallet proves against, concatenated in
// this documented order (the version bucket stores them all, so regenerating any one
// must change the version):
//   cat public/circuits/transfer.zkey circuits/out/transfer10x2.zkey public/circuits/withdraw.zkey circuits/out/deposit.zkey | sha256sum | cut -c1-8
// The proving-asset module keys its Cache Storage bucket on this
// ("bongtu-circuits-v<version>") and evicts any stale bucket, so a re-proven zkey forces
// a one-time re-download instead of serving a mismatched key from disk (a stale key fails
// on-chain verify with no self-heal). Bump this the moment ANY zkey changes on disk.
// A bump is live only with its two companions in the SAME change: upload the new
// assets (deploy/gates/upload_circuits.sh — refuses a hash that doesn't match this pin)
// and point vercel.json's /circuits rewrite at the new circuits/<version>/ path.
// (2109f115 -> f91bd0d2: transfer10 left the set — deprecated 2026-07-28 — and
// transfer10x2 joined it; the other three keys are unchanged.)
// (f91bd0d2 -> bb0115c4: withdraw regenerated for the stealth exit — recipient
// public input at pub[26], milestone-stealth slice B; the other three keys are
// byte-identical, verified against the served f91bd0d2 assets.)
export const CIRCUITS_VERSION = "bb0115c4";

// Exact byte sizes of the served proving assets — the download progress bar's
// denominator. Needed because the CDN strips/deflates Content-Length on some
// assets (br-compressed wasm), which would leave the bar indeterminate; these
// are the DECODED sizes, matching what the streaming reader counts. Re-pin
// alongside CIRCUITS_VERSION whenever a zkey/wasm changes:
//   stat -c "%n %s" public/circuits/*
/** The circuits with browser-served proving assets — one name per {wasm, zkey} pair
 *  under `circuitBaseUrl`, and the key every asset/download path is typed on.
 *  transfer10 (10-in / 10-out) is DEPRECATED (user decision 2026-07-28): it stays
 *  deployed on chain but the wallet never proves it, so its ~114 MB of assets left
 *  the download set for the 10-in / 2-out transfer10x2's. */
export type BrowserCircuit = "transfer" | "transfer10x2" | "withdraw" | "deposit";

export const CIRCUIT_ASSET_BYTES: Record<BrowserCircuit, { wasm: number; zkey: number }> = {
  transfer: { wasm: 3924469, zkey: 28903456 },
  // transfer10x2 is ~95 MB of zkey — 3x the 2x2 transfer — which is why the wallet
  // fetches it ONLY once note selection says a spend needs 3+ input notes, never on
  // screen open (sizes from circuits/out/, the same build the blob store serves).
  transfer10x2: { wasm: 4520070, zkey: 95008180 },
  withdraw: { wasm: 3884612, zkey: 24870344 },
  deposit: { wasm: 3364023, zkey: 6776800 },
};

export { H, B } from "@bongtu/core/network";
