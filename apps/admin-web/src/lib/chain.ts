// MetaMask tx wiring (SPEC §7 employer-mode: the browser sends the tx). Given
// prover calldata {a,b,c,pub} + the 2054-element ciphertext, call the live pool's
// disburseWithCiphertexts. This is the "calldata-submit wired" boundary — proving
// itself happens on the prover service (proverClient.ts), not the browser.

import { ethers } from "ethers";
import type { Calldata } from "@bongtu/sdk/proving";
import { GIWA_GAS_FLOOR_GWEI, POOL_ABI_FRAGMENTS, explorerTxUrl } from "@bongtu/sdk/network";

// The shared per-function ABI fragments (@bongtu/sdk/network) — only the four
// functions the admin app touches.
const POOL_ABI = [POOL_ABI_FRAGMENTS.disburseWithCiphertexts, POOL_ABI_FRAGMENTS.root, POOL_ABI_FRAGMENTS.nextLeafIndex, POOL_ABI_FRAGMENTS.B];

// The GIWA gas floor lives in @bongtu/sdk/network (ethers' auto-estimate
// overpays ~1500x); the sdk is data-only, so parseUnits happens here.
const GAS_PRICE = ethers.utils.parseUnits(GIWA_GAS_FLOOR_GWEI, "gwei");

interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
function ethereum(): Eip1193 {
  const eth = (globalThis as { ethereum?: Eip1193 }).ethereum;
  if (!eth) throw new Error("no injected wallet found (install/enable MetaMask)");
  return eth;
}

export interface DisburseSubmitResult {
  txHash: string;
  explorerUrl: string;
}

/** Connect MetaMask, send disburseWithCiphertexts, return the tx hash. */
export async function submitDisburse(
  poolAddr: string,
  calldata: Calldata,
  ciphertext: string[],
  explorerBase: string,
): Promise<DisburseSubmitResult> {
  if (ciphertext.length !== 2054) {
    throw new Error(`ciphertext length ${ciphertext.length} != 2054; assemble the batch first`);
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const provider = new ethers.providers.Web3Provider(ethereum() as any, "any");
  await provider.send("eth_requestAccounts", []);
  const pool = new ethers.Contract(poolAddr, POOL_ABI, provider.getSigner());
  const tx = await pool.disburseWithCiphertexts(
    calldata.a,
    calldata.b,
    calldata.c,
    calldata.pub,
    ciphertext,
    { gasPrice: GAS_PRICE },
  );
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: explorerTxUrl(tx.hash, explorerBase) };
}

/** Read the live pool head (root + nextLeafIndex) over an RPC — no wallet needed. */
export async function poolHead(rpc: string, poolAddr: string): Promise<{ root: string; nextLeafIndex: string; B: string }> {
  const provider = new ethers.providers.JsonRpcProvider(rpc);
  const pool = new ethers.Contract(poolAddr, POOL_ABI, provider);
  const [root, nli, b] = await Promise.all([pool.root(), pool.nextLeafIndex(), pool.B()]);
  return { root: root.toString(), nextLeafIndex: nli.toString(), B: b.toString() };
}
