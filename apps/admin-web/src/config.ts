// App-specific knobs only. The deployment-coupled chain facts (pool, token,
// chainId, RPC/explorer, arbiter public key, H/B, gas floor, ABI fragments)
// live in @bongtu/core/network — ONE home, equality-tested against
// deploy/addresses.91342.json — and are re-exposed here in the DEFAULTS shape
// the views consume. Everything is PUBLIC: the arbiter *public* key is the
// pool's stored authority pubkey, safe to ship in employer-mode. The arbiter
// PRIVATE key is entered only in auditor-mode and never lives in this file.

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
  // The pool's stored arbiter PUBLIC key (addresses.91342.json arbiterKeyX/Y).
  arbiterPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y] as [string, string],
  // The bongtu prover service (top-level prover/, Python FastAPI over rabbitsnark)
  // on the employer's GPU box. Overridable at build time via VITE_PROVER_URL —
  // the exact dotted expression below is what Vite statically replaces (a cast
  // or optional-chained form defeats the replacement and makes the override
  // inert); the typeof guard keeps the node test runtime (tsx, no Vite) alive.
  proverUrl:
    (typeof import.meta.env !== "undefined" && import.meta.env.VITE_PROVER_URL) ||
    "http://127.0.0.1:8700/prove",
  // A public-mode indexer for /head + /path; auditor-mode points at an arbiter indexer.
  // Defaults to the relative path `/indexer` (like the wallet): in dev the Vite proxy
  // forwards it to a localhost indexer, in prod the Vercel rewrite (vercel.json) forwards
  // it to the Funnel indexer — the browser only ever talks to its own origin. Overridable
  // at build time via VITE_INDEXER_URL; the dotted+typeof form matches proverUrl so Vite's
  // static replacement actually fires (an optional-chained form would make it inert).
  indexerUrl:
    (typeof import.meta.env !== "undefined" && import.meta.env.VITE_INDEXER_URL) ||
    "/indexer",
} as const;

export { H, B } from "@bongtu/core/network";
