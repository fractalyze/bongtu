// Chain plumbing: the BongtuPool ABI + viem ABI helpers. viem is a first-class
// repo dependency (no external heavyweight loader needed), and the built ABI is
// read straight off the Foundry artifact.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseAbi, type Abi, type AbiEvent } from "viem";

import { KEM_SECRET_KEY_BYTES } from "@bongtu/core/kem";
import { CHAIN_ID } from "@bongtu/core/network";

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = join(HERE, "..", "..", ".."); // apps/indexer/src -> repo root

/** Load a Foundry artifact ABI from contracts/out/<sol>.sol/<contract>.json. */
export function loadAbi(sol: string, contract: string): Abi {
  const p = join(REPO_ROOT, "contracts", "out", `${sol}.sol`, `${contract}.json`);
  return JSON.parse(readFileSync(p, "utf8")).abi as Abi;
}

// The PRE-KEM (V1) op-event shapes, frozen from the pool at b9f9440~1. The V2
// events append (kemBinding, kemCiphertext), which changes topic0 — so a V2-only
// interface would silently SKIP every pre-upgrade envelope event while the
// unchanged Appended/SubtreeAppended kept the mirror advancing (the lagging-
// indexer failure of pq-envelope-design.md §7). Carrying both fragment sets
// makes ingest span the upgrade block: viem decodeEventLog dispatches on topic0,
// and applyLogs detects the vintage per log by the presence of `kemBinding`.
const V1_EVENT_FRAGMENTS = [
  "event Deposited(uint256 indexed epoch, uint256 firstLeafIndex, uint256 oc0, uint256 oc1, uint256 amount, uint256[2] ecdhPublicKey, uint256[10] encryptedValuesForAuthority, uint256 encryptionNonce, uint256 root)",
  "event Transferred(uint256 indexed epoch, uint256[2] nullifiers, uint256[2] outputCommitments, uint256[2] ecdhPublicKey, uint256[4] encryptedValuesForReceiver0, uint256[4] encryptedValuesForReceiver1, uint256[16] encryptedValuesForAuthority, uint256 encryptionNonce, uint256 root)",
  "event Disbursed(uint256 indexed epoch, uint256 nullifier, uint256 subtreeRoot, uint256 disclosureHash, uint256[2] ecdhPublicKey, uint256 encryptionNonce, uint256 root)",
  "event Withdrawn(uint256 indexed epoch, uint256[2] nullifiers, uint256 amount, uint256 changeCommitment, uint256[2] ecdhPublicKey, uint256[13] encryptedValuesForAuthority, uint256 encryptionNonce, uint256 root)",
];

/** The BongtuPool ABI (events + view fns the indexer needs): the built (V2)
 *  artifact PLUS the frozen V1 op-event fragments — dual-ABI ingest. A plain
 *  viem `Abi` array (built JSON items ++ parseAbi'd V1 fragments); viem's
 *  decodeEventLog dispatches on topic0 across the combined set. */
export function poolAbi(): Abi {
  const abi = loadAbi("BongtuPool", "BongtuPool");
  const v1 = parseAbi(V1_EVENT_FRAGMENTS);
  return [...abi, ...v1];
}

/** Whether the combined ABI models the V2 (hybrid) op events — i.e. the built
 *  artifact carries `kemCiphertext` on Deposited. False == a V1-only build,
 *  which MUST NOT serve a KEM-epoch pool (kemBootGuardError). Takes the viem
 *  ABI array (the combined poolAbi()). */
export function abiKnowsKem(abi: Abi): boolean {
  return abi.some(
    (x) => x.type === "event" && x.name === "Deposited" && x.inputs.some((i) => i.name === "kemCiphertext"),
  );
}

/** Op-event fragments the ingest dispatches on that postdate the V2 artifact
 *  vintage. Unlike the KEM axis (conditioned on chain state), these ship
 *  in-repo, so a build missing one is stale UNCONDITIONALLY — and a stale
 *  build silently under-records: decodeEventLog throws on (and applyLogs skips)
 *  the unknown topic0 while the unchanged Appended logs keep the mirror and
 *  /health green (the same lagging-indexer failure of pq-envelope-design.md §7,
 *  one axis over). Takes the viem ABI array and checks the event names are
 *  present. Returns the one-line fatal error, else null. Pure, like
 *  kemBootGuardError. */
export function staleOpAbiError(abi: Abi): string | null {
  const names = new Set(abi.filter((x): x is AbiEvent => x.type === "event").map((ev) => ev.name));
  for (const wanted of ["Transferred10", "Transferred10x2"]) {
    if (!names.has(wanted)) {
      return `FATAL: this build's ABI lacks the ${wanted} event — a stale contracts/out (or apps/indexer/abi/BongtuPool.abi.json) silently skips every ${wanted} op while /health stays green. Rebuild the pool ABI (recipe: apps/indexer/abi/README.md).`;
    }
  }
  return null;
}

/**
 * Resolve the pool address + RPC + start block from env / addresses.<chainId>.json.
 * - RPC:        env RPC or LIVE_RPC or E2E_RPC, else the anvil default.
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
  // The arbiter's ML-KEM-768 decapsulation key (env AUTHORITY_KEM_KEY, hex) —
  // the PQ half of the hybrid envelope. Required in arbiter mode once the pool
  // is in a KEM epoch (kemBootGuardError refuses otherwise). NEVER logged.
  authorityKemKey?: Uint8Array | null;
  // Postgres connection string (env DATABASE_URL) — REQUIRED at runtime (U-I4
  // Postgres-only): the indexer persists its derived state (events / nullifiers /
  // leaves / notes / history + a block cursor) to Postgres and boot-RESUMES from
  // the cursor. index.ts refuses to boot without it (databaseUrlError below);
  // Indexer.ingest throws on a missing url as the belt. Optional in the TYPE only
  // so unit tests can drive applyLogs-level logic without a database.
  databaseUrl?: string | null;
}

/**
 * The boot-refusal check (U-I4 Postgres-only, no silent in-memory fallback):
 * returns the one-line error to print when DATABASE_URL is unset, else null.
 * Factored out of index.ts so the unit suite can pin the refusal without spawning.
 */
export function databaseUrlError(env: Record<string, string | undefined> = process.env): string | null {
  if (env.DATABASE_URL) return null;
  return "FATAL: DATABASE_URL is not set — the indexer is Postgres-only. Point DATABASE_URL at a Postgres instance, or run the bundled stack: docker compose up --build (postgres + indexer; see docker-compose.yml and .env.compose.example).";
}

/** Parse a bjj scalar from decimal ("123…") or hex ("0x…") — BigInt() accepts both. */
export function parseScalar(s: string): bigint {
  return BigInt(s.trim());
}

export function resolveConfig(): ChainConfig {
  const rpc = process.env.RPC || process.env.LIVE_RPC || process.env.E2E_RPC || "http://127.0.0.1:8545";
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
  const authorityKemKey = process.env.AUTHORITY_KEM_KEY ? parseKemKey(process.env.AUTHORITY_KEM_KEY) : null;
  // Required at runtime (index.ts fail-fasts via databaseUrlError before this).
  const databaseUrl = process.env.DATABASE_URL || null;
  return { rpc, pool, startBlock, authorityKey, authorityKemKey, databaseUrl };
}

/** Parse AUTHORITY_KEM_KEY (the 2400-byte ML-KEM-768 decapsulation key) from
 *  0x-optional hex. Same handling rule as AUTHORITY_KEY: never logged. The
 *  exact-length requirement is load-bearing: decapsulating with a truncated
 *  key throws mid-ingest, and noble's implicit rejection means other wrong
 *  keys surface only as false tamper alarms — so malformed material must die
 *  here, at boot. */
export function parseKemKey(s: string): Uint8Array {
  const h = s.trim().replace(/^0[xX]/, "");
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) {
    throw new Error("AUTHORITY_KEM_KEY must be an even-length hex string");
  }
  if (h.length / 2 !== KEM_SECRET_KEY_BYTES) {
    throw new Error(
      `AUTHORITY_KEM_KEY must be the ${KEM_SECRET_KEY_BYTES}-byte ML-KEM-768 decapsulation key (got ${h.length / 2} bytes)`,
    );
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

const ZERO32 = "0x" + "0".repeat(64);

/**
 * The KEM boot-guard decision (pq-envelope-design.md §7, mandatory): given the
 * pool's `arbiterKemPkHash(currentEpoch())`, refuse to serve when the chain is
 * in a KEM epoch (nonzero hash) but this process cannot honor it — either the
 * built ABI is V1-only (op envelopes would be SILENTLY skipped: parseLog
 * misses the new topic0 while Appended keeps the mirror green) or arbiter mode
 * lacks the decapsulation key (every V2 envelope would be undecryptable).
 * Returns the one-line fatal error, else null. Same fail-fast posture as
 * databaseUrlError; pure so the unit suite pins it without an RPC.
 */
export function kemBootGuardError(opts: {
  kemPkHash: string;
  arbiterMode: boolean;
  hasKemKey: boolean;
  abiKnowsKem: boolean;
  /** keccak256 of the ek embedded in AUTHORITY_KEM_KEY (null when keyless).
   *  Decapsulating with a wrong-but-well-formed key does not throw — implicit
   *  rejection yields pseudorandom ss — so without this check a stale/mispasted
   *  key would record a false "tamper" verdict against EVERY honest V2 op. */
  kemKeyPkHash: string | null;
}): string | null {
  if (opts.kemPkHash.toLowerCase() === ZERO32) return null; // pre-KEM epoch (or V1 pool)
  if (!opts.abiKnowsKem) {
    return "FATAL: the pool's arbiterKemPkHash(currentEpoch()) is nonzero but this build's ABI has no KEM event fields — a V1-ABI ingest silently under-records every op envelope while /health stays green. Rebuild contracts/out from the hybrid BongtuPool.";
  }
  if (opts.arbiterMode && !opts.hasKemKey) {
    return "FATAL: the pool's arbiterKemPkHash(currentEpoch()) is nonzero but AUTHORITY_KEM_KEY is unset — arbiter mode cannot decapsulate hybrid envelopes. Set AUTHORITY_KEM_KEY (the ML-KEM-768 decapsulation key) or run public mode.";
  }
  if (
    opts.arbiterMode &&
    opts.kemKeyPkHash !== null &&
    opts.kemKeyPkHash.toLowerCase() !== opts.kemPkHash.toLowerCase()
  ) {
    return "FATAL: AUTHORITY_KEM_KEY does not match the pool's arbiterKemPkHash(currentEpoch()) — its embedded encapsulation key hashes differently. Serving would record a false 'kem binding mismatch' tamper verdict against every honest op. Fix the key (rotated epoch? wrong env?) before starting.";
  }
  return null;
}
