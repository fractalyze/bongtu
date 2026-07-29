// App-specific knobs only. The deployment-coupled chain facts (pool, token,
// chainId, RPC/explorer, arbiter public key, H/B, gas floor, ABI fragments)
// live in @bongtu/core/network — ONE home, equality-tested against
// deploy/addresses.91342.json — and the KDF domain facts in
// @bongtu/client/identity KEY_DERIVATION (shared with wallet-web, so both apps
// derive the same key for the same account by construction). Everything here is
// PUBLIC: the arbiter *public* key is the pool's stored authority pubkey — the
// disburse/deposit circuits encrypt their authority envelope to it. No PRIVATE
// key ever lives in this app: the employer's bjj spending key is DERIVED from a
// MetaMask signature at login (@bongtu/client/derive) and held in memory only.

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
 * The prover-service base URL for this build: VITE_PROVER_URL when set,
 * otherwise the environment default — `/prover` in prod builds (a same-origin
 * path the deployment's rewrite forwards, like `/indexer`) and the service's
 * loopback bind in dev (the console and the GPU box share the dev machine).
 * Pure so the two defaults are testable under the node runner, where
 * `import.meta.env` is undefined.
 */
export function proverUrlFromEnv(envUrl: string | undefined, dev: boolean): string {
  // MIGRATION: VITE_PROVER_URL used to carry the full ENDPOINT ("…:8700/prove");
  // the adapter now appends /prove to a BASE, so an old deployment's value would
  // post to /prove/prove and 404 at pay time — long after the operator committed
  // to the run. Strip the endpoint back to its base rather than break on it.
  if (envUrl && envUrl.trim() !== "") return envUrl.trim().replace(/\/+$/, "").replace(/\/prove$/, "");
  return dev ? "http://127.0.0.1:8700" : "/prover";
}

export const DEFAULTS = {
  chainId: CHAIN_ID,
  rpc: RPC_URL,
  explorer: EXPLORER_BASE,
  // The official GIWA testnet-ETH faucet (docs.giwa.io/en/get-started/faucets) —
  // linked from the deposit dialog's zero-gas notice, same as the wallet, so an
  // operator whose account cannot pay for its own mint has a next step.
  gasFaucet: "https://faucet.giwa.io",
  pool: POOL_ADDRESS,
  token: TOKEN_ADDRESS,
  batchSize: B,
  // The pool's stored arbiter PUBLIC key (addresses.91342.json arbiterKeyX/Y):
  // the disburse builder's authority-envelope target. The contract injects the
  // SAME key from storage before verifying, so a mismatch fails the proof.
  arbiterPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y] as [string, string],
  // The arbiter-mode indexer for signed /notes (balance) + /head + signed /path
  // (membership). Relative `/indexer` reaches it same-origin: the Vite proxy in
  // dev, the Vercel rewrite (vercel.json) in prod.
  indexerUrl: viteEnv().VITE_INDEXER_URL || "/indexer",
  // The bongtu prover service (top-level prover/, FastAPI over rabbitsnark on
  // the employer's GPU box). ALL payroll proofs go there — this app never
  // proves in the browser.
  proverUrl: proverUrlFromEnv(viteEnv().VITE_PROVER_URL, Boolean(viteEnv().DEV)),
} as const;

// Build-time env, typed by assertion instead of the vite/client ImportMeta
// augmentation: this module is ALSO type-checked by the ROOT cross-tree
// tsconfig (deploy/live/giwa_payroll_e2e.ts imports the console's own modules),
// which has no Vite types — `import.meta.env?.` would not compile there. The
// optional access still survives Vite's static replacement and the plain node
// test runtime.
function viteEnv(): { VITE_INDEXER_URL?: string; VITE_PROVER_URL?: string; DEV?: boolean } {
  return (import.meta as { env?: { VITE_INDEXER_URL?: string; VITE_PROVER_URL?: string; DEV?: boolean } }).env ?? {};
}

export { H, B } from "@bongtu/core/network";
