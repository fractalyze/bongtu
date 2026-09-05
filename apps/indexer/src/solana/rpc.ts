// Live Solana JSON-RPC fetch layer (SOLR §3.2.2's canonical poll loop):
// getSignaturesForAddress paginated back to the stored cursor, getTransaction
// per signature (top-level + inner instructions), getAccountInfo for the
// TreeState head assert. Everything is converted to the indexer's internal
// 0x-hex byte convention at this edge, so wire.ts and the ingest layer never
// see base58. Correctness is gated by the recorded-ledger conformance leg
// driving the SAME apply layer (SOLR §5.3); this adapter is deliberately thin
// — the e2e_s.sh validator gate (S6) is what exercises it end to end.

import {
  CONFIG_OFF_BATCH_B,
  TREE_OFF_CONFIG,
  TREE_OFF_NEXT,
  TREE_OFF_ROOT,
  base58ToBytes,
  base58ToHex,
  bytesToBase58,
} from "@bongtu/core/solana";
import { hexOfBytes, type SolanaInstructionRecord, type SolanaLedgerTx } from "./wire.js";
import type { SolanaChainIo } from "./ingest.js";

/** Backend selection config (chain.ts `solana`): ids stay base58 in env, the
 *  operator-facing convention. */
export interface SolanaRpcConfig {
  rpc: string;
  programId: string;
  treeAccount: string;
}

interface RpcSignatureRow {
  signature: string;
  err: unknown;
}

// The getTransaction "json"-encoded shapes this adapter reads.
interface RpcCompiledIx {
  programIdIndex: number;
  accounts: number[];
  data: string; // base58
}
interface RpcTransaction {
  slot: number;
  blockTime: number | null;
  transaction: { message: { accountKeys: string[]; instructions: RpcCompiledIx[] } };
  meta: {
    err: unknown;
    innerInstructions?: { index: number; instructions: RpcCompiledIx[] }[];
    loadedAddresses?: { writable: string[]; readonly: string[] };
  } | null;
}

export class SolanaRpcIo implements SolanaChainIo {
  constructor(private readonly cfg: SolanaRpcConfig) {}

  private async call<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(this.cfg.rpc, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const body = (await res.json()) as { result?: T; error?: { message: string } };
    if (body.error) throw new Error(`solana rpc ${method}: ${body.error.message}`);
    return body.result as T;
  }

  private async accountData(pubkeyBase58: string): Promise<Uint8Array> {
    const info = await this.call<{ value: { data: [string, string] } | null }>("getAccountInfo", [
      pubkeyBase58,
      { encoding: "base64" },
    ]);
    if (!info.value) throw new Error(`solana rpc: account ${pubkeyBase58} does not exist`);
    return new Uint8Array(Buffer.from(info.value.data[0], "base64"));
  }

  async treeHead(): Promise<{ root: bigint; nextLeafIndex: number }> {
    const data = await this.accountData(this.cfg.treeAccount);
    const root = Array.from({ length: 32 }, (_, i) => data[TREE_OFF_ROOT + i]).reduce<bigint>(
      (acc, b) => (acc << 8n) | BigInt(b),
      0n,
    );
    const nli = Array.from({ length: 8 }, (_, i) => data[TREE_OFF_NEXT + i]).reduce<bigint>(
      (acc, b, i) => acc | (BigInt(b) << BigInt(8 * i)),
      0n,
    );
    return { root, nextLeafIndex: Number(nli) };
  }

  async batchSize(): Promise<number> {
    // TreeState links its PoolConfig (state.rs); B lives there — one env knob
    // (the tree account) resolves both.
    const tree = await this.accountData(this.cfg.treeAccount);
    const configKey = bytesToBase58(tree.subarray(TREE_OFF_CONFIG, TREE_OFF_CONFIG + 32));
    const config = await this.accountData(configKey);
    return config[CONFIG_OFF_BATCH_B] | (config[CONFIG_OFF_BATCH_B + 1] << 8) | (config[CONFIG_OFF_BATCH_B + 2] << 16) | (config[CONFIG_OFF_BATCH_B + 3] << 24);
  }

  async txsSince(untilSignature: string | null): Promise<SolanaLedgerTx[]> {
    // Newest-first pages back to the cursor, then replay oldest-first —
    // getSignaturesForAddress's `until` is exclusive, exactly the gap-only
    // resume semantics the cursor needs.
    const signatures: string[] = [];
    const page = async (before: string | null): Promise<void> => {
      const opts: Record<string, unknown> = { limit: 1000 };
      if (before !== null) opts.before = before;
      if (untilSignature !== null) opts.until = untilSignature;
      const rows = await this.call<RpcSignatureRow[]>("getSignaturesForAddress", [this.cfg.programId, opts]);
      for (const r of rows) {
        if (r.err === null) signatures.push(r.signature);
      }
      if (rows.length === 1000) await page(rows[rows.length - 1].signature);
    };
    await page(null);
    signatures.reverse();

    const txs: SolanaLedgerTx[] = [];
    for (const signature of signatures) {
      const t = await this.call<RpcTransaction | null>("getTransaction", [
        signature,
        { encoding: "json", maxSupportedTransactionVersion: 0 },
      ]);
      if (t === null || t.meta === null || t.meta.err !== null) continue; // failed txs move no state
      const keys = [
        ...t.transaction.message.accountKeys,
        ...(t.meta.loadedAddresses?.writable ?? []),
        ...(t.meta.loadedAddresses?.readonly ?? []),
      ].map(base58ToHex);
      // Accounts ride EVERY record, inner included: decodeOp reads meta 11
      // for the withdraw recipient token account, and a wrapper-invoked
      // withdraw arrives as an INNER instruction — dropping inner keys would
      // zero its announcement recipient.
      const toRecord = (ix: RpcCompiledIx): SolanaInstructionRecord => ({
        programId: keys[ix.programIdIndex],
        data: hexOfBytes(base58ToBytes(ix.data)),
        accounts: ix.accounts.map((a) => keys[a]),
      });
      const instructions = t.transaction.message.instructions.map(toRecord);
      const inner: SolanaInstructionRecord[][] = instructions.map(() => []);
      for (const group of t.meta.innerInstructions ?? []) {
        inner[group.index] = group.instructions.map(toRecord);
      }
      txs.push({
        slot: t.slot,
        blockTime: t.blockTime ?? 0,
        signature,
        instructions,
        inner,
      });
    }
    return txs;
  }
}
