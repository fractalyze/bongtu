// Shared plumbing for the validator acceptance legs (client_leg.ts,
// enterprise_leg.ts): deterministic actors, SPL genesis account images,
// validator/indexer process management, and a raw v1 instruction sender for
// the transactions the client package has no flow for (initialize, the
// enterprise fixture replays). Everything protocol-shaped comes from
// @bongtu/core / @bongtu/client-solana — this file owns only gate mechanics.

import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519.js";
import type { Instruction } from "@solana/kit";

import { base58ToBytes, bytesToBase58 } from "@bongtu/core/solana";
import { rpcCall, type SolanaConnection } from "@bongtu/client-solana/connection";
import { sendV1Instruction } from "@bongtu/client-solana/consumer";
import { LOADED_ACCOUNTS_DATA_SIZE_LIMIT } from "@bongtu/client-solana/txbuild";

// --- deterministic actors ----------------------------------------------------

export const sha = (label: string): Uint8Array => new Uint8Array(createHash("sha256").update(label).digest());

/** A 64-byte Solana secret key (seed || ed25519 pub) from a fixed label. */
export const secretKeyOf = (label: string): Uint8Array => {
  const seed = sha(label);
  const out = new Uint8Array(64);
  out.set(seed, 0);
  out.set(ed25519.getPublicKey(seed), 32);
  return out;
};

export const addressOfSecret = (sk: Uint8Array): string => bytesToBase58(sk.slice(32));

/** A 32-byte big-endian field encoding. */
export const be32 = (v: bigint): Uint8Array =>
  Uint8Array.from({ length: 32 }, (_, i) => Number((v >> BigInt(8 * (31 - i))) & 0xffn));

// --- genesis account images --------------------------------------------------

/** SPL mint image (82 B, consensus-fixed layout): no authorities, decimals 0,
 *  is_initialized = 1. */
export function mintImage(): Uint8Array {
  const data = new Uint8Array(82);
  data[45] = 1;
  return data;
}

/** SPL token account image (165 B): mint, owner, amount u64 LE, Initialized. */
export function tokenAccountImage(mint: string, owner: string, amount: bigint): Uint8Array {
  const data = new Uint8Array(165);
  data.set(base58ToBytes(mint), 0);
  data.set(base58ToBytes(owner), 32);
  for (const i of Array(8).keys()) data[64 + i] = Number((amount >> BigInt(8 * i)) & 0xffn);
  data[108] = 1;
  return data;
}

export function accountJson(
  dir: string,
  name: string,
  pubkey: string,
  owner: string,
  data: Uint8Array,
): string {
  const file = join(dir, `${name}.json`);
  writeFileSync(
    file,
    JSON.stringify({
      pubkey,
      account: {
        lamports: 1_000_000_000,
        data: [Buffer.from(data).toString("base64"), "base64"],
        owner,
        executable: false,
        rentEpoch: 0,
        space: data.length,
      },
    }),
  );
  return file;
}

// --- process + polling helpers -----------------------------------------------

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function waitFor(what: string, probe: () => Promise<boolean>, timeoutMs = 90_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const up = await probe().catch(() => false);
    if (up) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(400);
  }
}

/** The indexer reads at a stricter commitment than the legs' confirm, so a
 *  pool PDA can be confirmed for the leg while not yet existing for it. */
export async function waitForFinalized(rpc: string, addr: string): Promise<void> {
  await waitFor(`finalization of ${addr}`, async () => {
    const r = await rpcCall<{ value: unknown | null }>(rpc, "getAccountInfo", [
      addr,
      { commitment: "finalized", encoding: "base64" },
    ]);
    return r.value !== null;
  });
}

export async function airdrop(rpc: string, addr: string): Promise<void> {
  await rpcCall<string>(rpc, "requestAirdrop", [addr, 10_000_000_000]);
  await waitFor(`airdrop to ${addr}`, async () => {
    const r = await rpcCall<{ value: number }>(rpc, "getBalance", [addr, { commitment: "confirmed" }]);
    return r.value > 0;
  });
}

/** Spawn a `solana-test-validator` with the program and the given genesis
 *  account images (name, pubkey, owner, data). */
export function spawnValidator(opts: {
  scratch: string;
  rpcPort: number;
  soPath: string;
  programId: string;
  accounts: [string, string, string, Uint8Array][];
}): ChildProcess {
  const args = [
    "--reset",
    "--quiet",
    "--ledger",
    join(opts.scratch, "ledger"),
    "--rpc-port",
    String(opts.rpcPort),
    "--faucet-port",
    String(opts.rpcPort + 1000),
    "--bind-address",
    "127.0.0.1",
    "--bpf-program",
    opts.programId,
    opts.soPath,
    ...opts.accounts.flatMap(([name, pubkey, owner, data]) => [
      "--account",
      pubkey,
      accountJson(opts.scratch, name, pubkey, owner, data),
    ]),
  ];
  return spawn("solana-test-validator", args, { stdio: "ignore" });
}

/** Spawn the indexer (Solana backend) against a live validator. */
export function spawnIndexer(root: string, env: Record<string, string>): ChildProcess {
  return spawn(process.execPath, ["--import", "tsx", join(root, "apps", "indexer", "src", "index.ts")], {
    cwd: root,
    stdio: ["ignore", "inherit", "inherit"],
    env: { ...process.env, ...env },
  });
}

// --- raw instruction submit --------------------------------------------------

/**
 * Send ONE instruction as a Transaction v1 with an explicit CU limit — the
 * package's one v1-assembly path (@bongtu/client-solana sendV1Instruction),
 * for the transactions no client flow owns. Kit stays un-imported here: the
 * hoisted root @solana/kit predates the v1 config API, so tx assembly must
 * resolve through the package's own pinned kit.
 */
export function sendInstruction(
  connection: SolanaConnection,
  ix: Instruction,
  computeUnitLimit: number,
): Promise<string> {
  return sendV1Instruction(connection, ix, {
    computeUnitLimit,
    loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  });
}