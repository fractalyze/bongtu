// The ONE pool call @bongtu/client does not carry: disburseWithCiphertexts —
// payroll's terminal 1-in/256-out transaction, with its 2054-element on-chain
// ciphertext arg (SPEC §7 employer-mode). Everything else about talking to the
// chain is the shared engine: the `Connection` comes from lib/connect.ts, the
// viem chain object + pinned gas price from @bongtu/client/chain, and the
// KEM-epoch guard runs in the flow (client assertPoolKemEpoch) before any proof
// is even started — so this module is only the submit.

import { parseAbi, type Address } from "viem";
import type { Calldata } from "@bongtu/core/proving";
import { POOL_ABI_FRAGMENTS, explorerTxUrl } from "@bongtu/core/network";
import { liveChain } from "@bongtu/client/chain";
import type { Connection } from "@bongtu/client/connection";

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
  const hash = await connection.walletClient.writeContract({
    address: poolAddr as Address,
    abi: POOL_ABI,
    functionName: "disburseWithCiphertexts",
    args: [
      calldata.a.map(BigInt) as [bigint, bigint],
      calldata.b.map((r) => r.map(BigInt)) as [[bigint, bigint], [bigint, bigint]],
      calldata.c.map(BigInt) as [bigint, bigint],
      calldata.pub.map(BigInt) as unknown as readonly [
        bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint,
      ],
      ciphertext.map(BigInt),
      kemCiphertext as `0x${string}`,
    ],
    account: connection.address as Address,
    chain: liveChain,
    // Pinned, never estimated: wallet-stack auto-estimation once overpaid ~1500x.
    // 3x headroom over the floor quote — same rationale as the client submits.
    gasPrice: (await connection.publicClient.getGasPrice()) * 3n,
    // Chain-derived nonce, same rationale as the client submits: the wallet's
    // tracker desyncs after speed-up/cancel surgery.
    nonce: await connection.publicClient.getTransactionCount({
      address: connection.address as Address,
      blockTag: "pending",
    }),
  });
  await connection.publicClient.waitForTransactionReceipt({ hash });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash, explorerBase) };
}
