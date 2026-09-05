// connection/edge.ts — the Solana rail's Connection shape and everything that
// operates on a live one: the hand-rolled JSON-RPC reads (the
// apps/indexer/src/solana/rpc.ts precedent — ids stay base58 at the operator
// edge, bytes inside), the cluster guard (the ensureChain analogue: pinned
// genesis hash asserted BEFORE anything signs), the key-derivation signMessage
// edge, and the explorer link. How a browser REACHES a wallet (wallet-standard
// adapters, Phantom's injected provider) is the app layer's business; it turns
// whatever it connected into the `SolanaConnection` this module consumes.

import type { Transaction } from "@solana/kit";
import type { Connection as RailConnection } from "@bongtu/client/rail";
import { bytesToBase58 } from "@bongtu/core/solana";
import type { SolanaKdfConfig } from "../derive.js";
import { keyDerivationPayload } from "../derive.js";

/**
 * A connected Solana wallet, whatever it is connected through. Extends the
 * engine's structural rail seam (`address` + `transport`) with the rail's own
 * edges: the RPC endpoint the flows read through, the wallet-standard
 * `solana:signMessage` (the KDF seed source — RFC 8032-deterministic for the
 * supported local-signer wallet class, see identity.ts for the guard on the
 * rest), and sign-and-send over a compiled transaction.
 */
export interface SolanaConnection extends RailConnection {
  /** the cluster JSON-RPC endpoint every read and submit goes through. */
  rpcUrl: string;
  /** wallet-standard solana:signMessage over raw bytes -> 64-byte ed25519
   *  signature. The ONLY payload this client ever submits here is the
   *  key-derivation template (derive.ts). */
  signMessage(bytes: Uint8Array): Promise<Uint8Array>;
  /** Sign the compiled transaction as fee payer and send it; resolves to the
   *  transaction signature (base58). Confirmation is the SUBMIT layer's job
   *  (consumer.ts polls it), mirroring wallet-standard signAndSendTransaction
   *  which also returns at send time. */
  signAndSendTransaction(tx: Transaction): Promise<string>;
}

// --- JSON-RPC (hand-rolled fetch, the indexer rpc.ts precedent) --------------

interface RpcError {
  message: string;
}

/** One JSON-RPC call. Exported for the rail-internal callers (submits, the
 *  gate driver); apps read chain state through the indexer feed, not this. */
export async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await res.json()) as { result?: T; error?: RpcError };
  if (body.error) throw new Error(`solana rpc ${method}: ${body.error.message}`);
  return body.result as T;
}

/** The cluster genesis hash, base58 verbatim — compared against the PINNED
 *  value by ensureSolanaCluster, never fed into the KDF directly (derive.ts
 *  rule 3: a lying RPC may block login, never steer the key). */
export function getGenesisHash(rpcUrl: string): Promise<string> {
  return rpcCall<string>(rpcUrl, "getGenesisHash", []);
}

/** A recent blockhash for transaction lifetimes. */
export async function getLatestBlockhash(
  rpcUrl: string,
): Promise<{ blockhash: string; lastValidBlockHeight: bigint }> {
  const r = await rpcCall<{ value: { blockhash: string; lastValidBlockHeight: number } }>(
    rpcUrl,
    "getLatestBlockhash",
    [{ commitment: "confirmed" }],
  );
  return { blockhash: r.value.blockhash, lastValidBlockHeight: BigInt(r.value.lastValidBlockHeight) };
}

/** Raw account data (base64-decoded), or null when the account does not exist. */
export async function getAccountData(rpcUrl: string, addressBase58: string): Promise<Uint8Array | null> {
  const r = await rpcCall<{ value: { data: [string, string] } | null }>(rpcUrl, "getAccountInfo", [
    addressBase58,
    { encoding: "base64", commitment: "confirmed" },
  ]);
  if (!r.value) return null;
  return Uint8Array.from(atob(r.value.data[0]), (c) => c.charCodeAt(0));
}

/** SPL token account balance in raw units; 0n when the account is absent
 *  (an unfunded wallet reads as empty, not as an error). */
export async function getTokenBalance(rpcUrl: string, tokenAccountBase58: string): Promise<bigint> {
  const data = await getAccountData(rpcUrl, tokenAccountBase58);
  if (data === null) return 0n;
  // amount u64 LE at offset 64 (the consensus-fixed SPL token Account layout,
  // chains/solana/program/src/spl.rs).
  return Array.from({ length: 8 }, (_, i) => data[64 + i]).reduce<bigint>(
    (acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)),
    0n,
  );
}

/** Poll a submitted signature to confirmation. Throws on an on-chain error and
 *  on timeout — an unconfirmed submit must never resolve as a SubmitResult. */
export async function confirmSignature(
  rpcUrl: string,
  signature: string,
  opts: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<void> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const intervalMs = opts.intervalMs ?? 400;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const r = await rpcCall<{ value: ({ confirmationStatus?: string; err: unknown } | null)[] }>(
      rpcUrl,
      "getSignatureStatuses",
      [[signature], { searchTransactionHistory: false }],
    );
    const s = r.value[0];
    if (s && s.err) throw new Error(`transaction ${signature} failed on-chain: ${JSON.stringify(s.err)}`);
    if (s && (s.confirmationStatus === "confirmed" || s.confirmationStatus === "finalized")) return;
    if (Date.now() > deadline) throw new Error(`transaction ${signature} was not confirmed in ${timeoutMs}ms`);
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

// --- the cluster guard (the ensureChain analogue) ----------------------------

/**
 * Refuse to proceed on any cluster other than the pinned one: the live
 * getGenesisHash must equal the deployment's pinned genesis hash. runLogin
 * calls this BEFORE the derivation popup (the same ordering the EVM chain
 * guard enforces), so the RPC can block a login but never steer which key the
 * payload derives — the pinned value, not the RPC's answer, goes into the
 * template (derive.ts rule 3).
 */
export async function ensureSolanaCluster(connection: SolanaConnection, expectedGenesisHash: string): Promise<void> {
  const live = await getGenesisHash(connection.rpcUrl);
  if (live !== expectedGenesisHash) {
    throw new Error(
      `This RPC serves a different Solana cluster (genesis ${live}) than the pool's ` +
        `(genesis ${expectedGenesisHash}). Point the wallet at the pool's cluster and try again.`,
    );
  }
}

// --- the key-derivation signing edge ----------------------------------------

/**
 * Ask the wallet to signMessage the domain-separated derivation payload and
 * return the signature as 0x-hex — the byte form the rail-agnostic KDF
 * (@bongtu/client/derive deriveIdentityFromSignature) consumes. The 64-vs-65
 * byte difference from the EVM signature is irrelevant to the KDF (it hashes
 * whatever bytes arrive); what matters is determinism, guarded in identity.ts.
 */
export async function signKeyDerivation(connection: SolanaConnection, kdf: SolanaKdfConfig): Promise<string> {
  const sig = await connection.signMessage(keyDerivationPayload(kdf));
  return "0x" + Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("");
}

// --- explorer ---------------------------------------------------------------

/** Explorer transaction link. `explorerBase` is app config, exactly as the EVM
 *  explorerTxUrl's base is; the default shape is the public explorer's /tx. */
export function solanaExplorerTxUrl(signature: string, explorerBase: string): string {
  return `${explorerBase.replace(/\/$/, "")}/tx/${signature}`;
}

/** base58 of raw 32 bytes — re-exported convenience over the ONE shared codec
 *  (@bongtu/core/solana), so callers never grow a second base58. */
export const addressFromBytes = (bytes: Uint8Array): string => bytesToBase58(bytes);
