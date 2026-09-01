// Env resolution for the relayer — the same shape and fallbacks as the indexer's
// chain.ts resolveConfig (one convention for "which pool on which chain"):
// RPC defaults to local anvil, POOL falls back to the canonical deploy record
// deploy/addresses.<CHAIN_ID>.json, CHAIN_ID defaults to the sdk's. What is NEW
// here is SUBMITTER_KEY — the funded EOA private key that pays every relayed
// withdraw's gas. It is REQUIRED (submitterKeyError below is the boot-refusal
// check, same fail-fast posture as the indexer's databaseUrlError) and is NEVER
// logged or returned over HTTP: the only public trace of it is the submitter
// ADDRESS in /health.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CHAIN_ID } from "@bongtu/core/network";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(HERE, "..", "..", ".."); // apps/relayer/src -> repo root

export interface RelayerConfig {
  rpc: string;
  pool: string;
  chainId: number;
  port: number;
  // The submitter EOA private key (0x-hex). NEVER logged, NEVER in a response —
  // it exists only to sign the relayed withdraw txs. Optional in the TYPE only
  // so unit tests can build configs without material; index.ts refuses to boot
  // without it (submitterKeyError).
  submitterKey?: string | null;
}

/**
 * The boot-refusal check (mirrors the indexer's databaseUrlError): returns the
 * one-line error to print when SUBMITTER_KEY is unset, else null. Factored out
 * of index.ts so the unit suite can pin the refusal without spawning.
 */
export function submitterKeyError(env: Record<string, string | undefined> = process.env): string | null {
  if (env.SUBMITTER_KEY) return null;
  return "FATAL: SUBMITTER_KEY is not set — the relayer signs every sponsored withdraw with this funded EOA key and refuses to boot without it. Set SUBMITTER_KEY to a 0x-hex private key holding gas ETH.";
}

export function resolveConfig(env: Record<string, string | undefined> = process.env): RelayerConfig {
  const rpc = env.RPC || "http://127.0.0.1:8545";
  const chainId = env.CHAIN_ID ? Number(env.CHAIN_ID) : CHAIN_ID;
  // Same fallback the indexer uses: the canonical deploy record BY FIELD NAME
  // (CLAUDE.md: never transcribe an address by pattern-matching an older value).
  const pool: string = env.POOL || (() => {
    const addrPath = join(REPO_ROOT, "deploy", `addresses.${chainId}.json`);
    return JSON.parse(readFileSync(addrPath, "utf8")).pool;
  })();
  if (!pool) throw new Error("no pool address (set POOL env or deploy/addresses.<CHAIN_ID>.json)");
  const port = env.PORT ? Number(env.PORT) : 8700;
  const submitterKey = env.SUBMITTER_KEY || null;
  return { rpc, pool, chainId, port, submitterKey };
}
