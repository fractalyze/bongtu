// Env resolution for the sweeper — the same shape and fallbacks as the relayer's
// config.ts (one convention for "which pool on which chain"): RPC defaults to
// local anvil, POOL falls back to the canonical deploy record
// deploy/addresses.<CHAIN_ID>.json. What is NEW here:
//
//   SWEEPER_KEY   the factory-owner EOA private key — PortalFactory.sweep is
//                 onlyOwner (the Slice ⑤ trust concession), so this key is what
//                 makes the bot ABLE to sweep at all. REQUIRED (bootError below
//                 is the boot-refusal check, same fail-fast posture as the
//                 relayer's SUBMITTER_KEY) and NEVER logged or served: the only
//                 public trace of it is the sweeper ADDRESS in /health.
//   INDEXER_URL   where the /portal/unswept work feed lives — the bot is a pure
//                 consumer of the indexer's issuance registry (it never derives
//                 addresses itself), so without it there is no work source and
//                 the boot refuses just as clearly.
//   FACTORY       the PortalFactory to sweep through. Falls back to the deploy
//                 record's `portalFactory` field BY NAME (live wiring is U-P4,
//                 so the field may not exist yet — a missing factory throws in
//                 resolveConfig, the relayer's missing-pool posture).
//   TOKEN         the ERC-20 whose balance at each portal destination decides
//                 "funded" (default: the sdk TOKEN_ADDRESS — the live kKRW).
//   POLL_MS       rescan period (default 15000). Retries ARE the rescan: a
//                 record that stays unswept simply comes around again.
//   CIRCUITS_OUT  where deposit.zkey / deposit_js/deposit.wasm live for the
//                 CPU snarkjs prover (default <repo>/circuits/out).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { CHAIN_ID, TOKEN_ADDRESS } from "@bongtu/core/network";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(HERE, "..", "..", ".."); // apps/sweeper/src -> repo root

export interface SweeperConfig {
  rpc: string;
  pool: string;
  factory: string;
  token: string;
  chainId: number;
  port: number;
  pollMs: number;
  circuitsOut: string;
  indexerUrl: string;
  // The factory-owner EOA private key (0x-hex). NEVER logged, NEVER in a
  // response — it exists only to sign sweep txs. Optional in the TYPE only so
  // unit tests can build configs without material; index.ts refuses to boot
  // without it (bootError).
  sweeperKey?: string | null;
}

/**
 * The boot-refusal check (mirrors the relayer's submitterKeyError): returns the
 * one-line error to print for the FIRST missing required variable, else null.
 * Factored out of index.ts so the unit suite can pin the refusal without
 * spawning.
 */
export function bootError(env: Record<string, string | undefined> = process.env): string | null {
  if (!env.SWEEPER_KEY) {
    return "FATAL: SWEEPER_KEY is not set — the sweeper signs every PortalFactory.sweep with this factory-owner EOA key (sweep is onlyOwner) and refuses to boot without it. Set SWEEPER_KEY to a 0x-hex private key holding gas ETH.";
  }
  if (!env.INDEXER_URL) {
    return "FATAL: INDEXER_URL is not set — the sweeper's only work source is the indexer's GET /portal/unswept feed and it refuses to boot without one. Set INDEXER_URL to the indexer's base URL.";
  }
  return null;
}

export function resolveConfig(env: Record<string, string | undefined> = process.env): SweeperConfig {
  const rpc = env.RPC || "http://127.0.0.1:8545";
  const chainId = env.CHAIN_ID ? Number(env.CHAIN_ID) : CHAIN_ID;
  // Same fallback the relayer/indexer use: the canonical deploy record BY FIELD
  // NAME (CLAUDE.md: never transcribe an address by pattern-matching).
  const record: Record<string, string> | null = (() => {
    if (env.POOL && env.FACTORY) return null; // both given — no file read needed
    const addrPath = join(REPO_ROOT, "deploy", `addresses.${chainId}.json`);
    try {
      return JSON.parse(readFileSync(addrPath, "utf8")) as Record<string, string>;
    } catch {
      return null;
    }
  })();
  const pool = env.POOL || record?.pool || "";
  if (!pool) throw new Error("no pool address (set POOL env or deploy/addresses.<CHAIN_ID>.json)");
  const factory = env.FACTORY || record?.portalFactory || "";
  if (!factory) {
    throw new Error(
      "no PortalFactory address (set FACTORY env, or a `portalFactory` field in deploy/addresses.<CHAIN_ID>.json once the live factory is wired)",
    );
  }
  const token = env.TOKEN || TOKEN_ADDRESS;
  const port = env.PORT ? Number(env.PORT) : 8710;
  const pollMs = env.POLL_MS ? Number(env.POLL_MS) : 15000;
  const circuitsOut = env.CIRCUITS_OUT || join(REPO_ROOT, "circuits", "out");
  const indexerUrl = env.INDEXER_URL || "";
  const sweeperKey = env.SWEEPER_KEY || null;
  return { rpc, pool, factory, token, chainId, port, pollMs, circuitsOut, indexerUrl, sweeperKey };
}
