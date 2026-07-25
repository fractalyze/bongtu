// MetaMask tx wiring (SPEC §7 employer-mode: the browser sends the tx). Given
// prover calldata {a,b,c,pub} + the 2054-element ciphertext, call the live pool's
// disburseWithCiphertexts. This is the "calldata-submit wired" boundary — proving
// itself happens in the local GPU helper (proverClient.ts), not the browser.

import { ethers } from "ethers";
import type { Calldata } from "@bongtu/prover-cli/types";

// A minimal hand-written ABI (avoids importing the Foundry artifact JSON). Only the
// four functions the admin app touches.
const POOL_ABI = [
  "function disburseWithCiphertexts(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[10] pub, uint256[] receiverCiphertexts)",
  "function root() view returns (uint256)",
  "function nextLeafIndex() view returns (uint256)",
  "function B() view returns (uint256)",
];

// GIWA wants ~0.001 gwei; ethers' auto-estimate overpays ~1500x. 0.005 gwei is a
// safe floor (matches deploy/giwa_disburse256.ts).
const GAS_PRICE = ethers.utils.parseUnits("0.005", "gwei");

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
  return { txHash: tx.hash, explorerUrl: `${explorerBase}/tx/${tx.hash}` };
}

/** Read the live pool head (root + nextLeafIndex) over an RPC — no wallet needed. */
export async function poolHead(rpc: string, poolAddr: string): Promise<{ root: string; nextLeafIndex: string; B: string }> {
  const provider = new ethers.providers.JsonRpcProvider(rpc);
  const pool = new ethers.Contract(poolAddr, POOL_ABI, provider);
  const [root, nli, b] = await Promise.all([pool.root(), pool.nextLeafIndex(), pool.B()]);
  return { root: root.toString(), nextLeafIndex: nli.toString(), B: b.toString() };
}
