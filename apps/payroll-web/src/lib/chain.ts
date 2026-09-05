// The ONE pool call @bongtu/client does not carry: disburseWithCiphertexts —
// payroll's terminal 1-in/256-out transaction, with its 2054-element on-chain
// ciphertext arg (SPEC §7 employer-mode). Everything else about talking to the
// chain is the shared engine: the `Connection` comes from lib/connect.ts, the
// KEM-epoch guard runs in the flow (client assertPoolKemEpoch) before any proof
// is even started, and the submit discipline — the gas pin, the chain-derived
// nonce, the receipt wait — is client submitPoolWrite. This module is only the
// ABI fragment plus the argument belts.

import { parseAbi } from "viem";
import type { Calldata } from "@bongtu/core/proving";
import { POOL_ABI_FRAGMENTS, explorerTxUrl } from "@bongtu/core/network";
import { submitPoolWrite, type Connection } from "@bongtu/client-evm/connection";

const POOL_ABI = parseAbi([POOL_ABI_FRAGMENTS.disburseWithCiphertexts]);

export interface DisburseSubmitResult {
  txHash: string;
  explorerUrl: string;
}

/** Send disburseWithCiphertexts through the connected wallet and wait for the
 *  receipt. `kemCiphertext` is the batch's 1088-byte ML-KEM ct (AssembleResult
 *  passthrough — the SAME encapsulation the proof's kemBinding committed to). */
export async function submitDisburse(
  connection: Connection,
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
  const hash = await submitPoolWrite(connection, {
    address: poolAddr,
    abi: POOL_ABI,
    functionName: "disburseWithCiphertexts",
    args: [
      calldata.a.map(BigInt),
      calldata.b.map((r) => r.map(BigInt)),
      calldata.c.map(BigInt),
      calldata.pub.map(BigInt),
      ciphertext.map(BigInt),
      kemCiphertext,
    ],
  });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash, explorerBase) };
}
