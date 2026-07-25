// Chain plumbing: load ethers v5 + the BongtuPool ABI without adding a repo dep.
//
// ethers v5 loads from the external node_modules via the sdk's shared loader
// (@bongtu/sdk/extern — the locked no-repo-local-install decision), so it comes
// back as `any` — we type OUR code, not ethers.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { loadEthers } from "@bongtu/sdk/extern";
import { CHAIN_ID } from "@bongtu/sdk/network";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(HERE, "..", "..", ".."); // apps/indexer/src -> repo root

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const ethers: any = loadEthers();

/** Load a Foundry artifact ABI from contracts/out/<sol>.sol/<contract>.json. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function loadAbi(sol: string, contract: string): any {
  const p = join(REPO_ROOT, "contracts", "out", `${sol}.sol`, `${contract}.json`);
  return JSON.parse(readFileSync(p, "utf8")).abi;
}

/** The BongtuPool ABI (events + view fns the indexer needs). */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function poolAbi(): any {
  return loadAbi("BongtuPool", "BongtuPool");
}

/**
 * Resolve the pool address + RPC + start block from env / addresses.<chainId>.json.
 * - RPC:        env RPC or GIWA_RPC or E2E_RPC, else the anvil default.
 * - POOL:       env POOL, else deploy/addresses.<chainId>.json `pool`.
 * - START_BLOCK env (default 0) — where the log replay begins.
 */
export interface ChainConfig {
  rpc: string;
  pool: string;
  startBlock: number;
  // The arbiter PRIVATE key (a bjj scalar). Set => ARBITER MODE: the indexer
  // decrypts every op's authority envelope, builds a note ledger, serves /notes,
  // and can fold within-batch merkle paths. Undefined/null => PUBLIC MODE (no
  // /notes, batch /path 422s). NEVER logged or returned over HTTP.
  authorityKey?: bigint | null;
}

/** Parse a bjj scalar from decimal ("123…") or hex ("0x…") — BigInt() accepts both. */
export function parseScalar(s: string): bigint {
  return BigInt(s.trim());
}

export function resolveConfig(): ChainConfig {
  const rpc = process.env.RPC || process.env.GIWA_RPC || process.env.E2E_RPC || "http://127.0.0.1:8545";
  const startBlock = process.env.START_BLOCK ? Number(process.env.START_BLOCK) : 0;
  let pool = process.env.POOL || "";
  if (!pool) {
    const chainId = process.env.CHAIN_ID || String(CHAIN_ID);
    const addrPath = join(REPO_ROOT, "deploy", `addresses.${chainId}.json`);
    pool = JSON.parse(readFileSync(addrPath, "utf8")).pool;
  }
  if (!pool) throw new Error("no pool address (set POOL env or deploy/addresses.<chainId>.json)");
  // Arbiter mode is gated purely on AUTHORITY_KEY presence (the arbiter private key).
  const authorityKey = process.env.AUTHORITY_KEY ? parseScalar(process.env.AUTHORITY_KEY) : null;
  return { rpc, pool, startBlock, authorityKey };
}
