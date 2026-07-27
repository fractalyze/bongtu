// MetaMask tx wiring (SPEC §7 employer-mode: the browser sends the tx). Given
// prover calldata {a,b,c,pub} + the 2054-element ciphertext, call the live pool's
// disburseWithCiphertexts. This is the "calldata-submit wired" boundary — proving
// itself happens on the prover service (proverClient.ts), not the browser.

import { ethers } from "ethers";
import type { Calldata } from "@bongtu/core/proving";
import {
  GIWA_GAS_FLOOR_GWEI,
  POOL_ABI_FRAGMENTS,
  arbiterKemPkGuardError,
  explorerTxUrl,
  isPreKemProbeError,
} from "@bongtu/core/network";

// The shared per-function ABI fragments (@bongtu/core/network) — only the
// functions the admin app touches: the disburse submit plus the KEM-epoch guard
// it runs first. The pool head (root / nextLeafIndex / B) is NOT read here — the
// indexer's /head is the live path for that (indexerClient.ts).
const POOL_ABI = [
  POOL_ABI_FRAGMENTS.disburseWithCiphertexts,
  POOL_ABI_FRAGMENTS.currentEpoch,
  POOL_ABI_FRAGMENTS.arbiterKemPkHash,
];

// The GIWA gas floor lives in @bongtu/core/network (ethers' auto-estimate
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

/** Connect MetaMask, send disburseWithCiphertexts, return the tx hash.
 *  `kemCiphertext` is the batch's 1088-byte ML-KEM ct (AssembleResult
 *  passthrough — the SAME encapsulation the proof's kemBinding committed to). */
export async function submitDisburse(
  poolAddr: string,
  calldata: Calldata,
  ciphertext: string[],
  kemCiphertext: string,
  explorerBase: string,
): Promise<DisburseSubmitResult> {
  if (ciphertext.length !== 2054) {
    throw new Error(`ciphertext length ${ciphertext.length} != 2054; assemble the batch first`);
  }
  if (!/^0x[0-9a-fA-F]+$/.test(kemCiphertext) || (kemCiphertext.length - 2) / 2 !== 1088) {
    throw new Error(`kemCiphertext must be 1088 bytes of 0x-hex; assemble the batch first`);
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const provider = new ethers.providers.Web3Provider(ethereum() as any, "any");
  await provider.send("eth_requestAccounts", []);
  const pool = new ethers.Contract(poolAddr, POOL_ABI, provider.getSigner());
  // The batch's kemCiphertext was encapsulated to the bundled ARBITER_KEM_PK at
  // assemble time; before it leaves the machine, require the chain to vouch for
  // that key (design doc §4/§5) — a pre-KEM or foreign-keyed pool fails with a
  // readable error instead of an unlabeled revert / undecryptable envelope.
  let onchainKemPkHash: string | null;
  try {
    onchainKemPkHash = String(await pool.arbiterKemPkHash(await pool.currentEpoch()));
  } catch (e) {
    if (!isPreKemProbeError(e)) throw e;
    onchainKemPkHash = null;
  }
  const kemGuard = arbiterKemPkGuardError(onchainKemPkHash);
  if (kemGuard) throw new Error(kemGuard);
  const tx = await pool.disburseWithCiphertexts(
    calldata.a,
    calldata.b,
    calldata.c,
    calldata.pub,
    ciphertext,
    kemCiphertext,
    { gasPrice: GAS_PRICE },
  );
  await tx.wait();
  return { txHash: tx.hash, explorerUrl: explorerTxUrl(tx.hash, explorerBase) };
}
