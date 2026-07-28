// MetaMask tx wiring (SPEC §7 employer-mode: the browser sends the tx). Given
// prover calldata {a,b,c,pub} + the 2054-element ciphertext, call the live pool's
// disburseWithCiphertexts. This is the "calldata-submit wired" boundary — proving
// itself happens on the prover service (proverClient.ts), not the browser.
//
// viem over the injected EIP-1193 provider (the same stack wallet-web runs on):
// a walletClient for the write, a publicClient on the GIWA RPC for the KEM-epoch
// probe reads and the receipt wait.

import {
  createPublicClient,
  createWalletClient,
  custom,
  defineChain,
  http,
  parseAbi,
  parseGwei,
  type Address,
  type PublicClient,
} from "viem";
import type { Calldata } from "@bongtu/core/proving";
import { causeChain } from "@bongtu/core/errors";
import {
  CHAIN_ID,
  EXPLORER_BASE,
  RPC_URL,
  GIWA_GAS_FLOOR_GWEI,
  POOL_ABI_FRAGMENTS,
  arbiterKemPkGuardError,
  explorerTxUrl,
  isPreKemProbeError,
} from "@bongtu/core/network";

// GIWA Sepolia as a viem chain, derived field-for-field from @bongtu/core/network
// (the ONE home of the chain facts) — identical to wallet-web/src/lib/chain.ts so a
// chain move cannot fork the admin app's idea of the network from the sdk's.
const giwaSepolia = defineChain({
  id: CHAIN_ID,
  name: "GIWA Sepolia (Testnet)",
  nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: "GIWA Sepolia Blockscout", url: EXPLORER_BASE } },
  testnet: true,
});

// The shared per-function ABI fragments (@bongtu/core/network), parsed once for
// viem — only the functions the admin app touches: the disburse submit plus the
// KEM-epoch guard it runs first. The pool head (root / nextLeafIndex / B) is NOT
// read here — the indexer's /head is the live path for that (indexerClient.ts).
const POOL_ABI = parseAbi([
  POOL_ABI_FRAGMENTS.disburseWithCiphertexts,
  POOL_ABI_FRAGMENTS.currentEpoch,
  POOL_ABI_FRAGMENTS.arbiterKemPkHash,
]);

// The pinned per-tx gas price (wei). GIWA wants ~0.001 gwei and wallet-stack
// auto-estimation historically overpaid ~1500x (drained the faucet grant), so the
// tx pins this instead of estimating (@bongtu/core/network GIWA_GAS_FLOOR_GWEI).
const GAS_PRICE = parseGwei(GIWA_GAS_FLOOR_GWEI);

// Reads (the KEM-epoch probe, the receipt wait) go straight to the GIWA RPC via
// one public client — never through the wallet.
const publicClient: PublicClient = createPublicClient({ chain: giwaSepolia, transport: http() });

interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}
function ethereum(): Eip1193 {
  const eth = (globalThis as { ethereum?: Eip1193 }).ethereum;
  if (!eth) throw new Error("no injected wallet found (install/enable MetaMask)");
  return eth;
}

/** viem's shape of "the getter is missing / reverted": a pre-KEM V1 pool probe.
 *  Transport failures (HttpRequestError etc.) carry none of these names and fall
 *  through — folding them in would fail the guard OPEN on an RPC hiccup. Mirrors
 *  wallet-web/src/lib/connection.ts; isPreKemProbeError still catches the ethers
 *  CALL_EXCEPTION shape for any legacy path. */
function isViemPreKemProbeError(e: unknown): boolean {
  return causeChain(e).some(
    (o) =>
      o.name === "ContractFunctionRevertedError" ||
      o.name === "ContractFunctionZeroDataError" ||
      o.name === "AbiDecodingZeroDataError",
  );
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
  const injected = ethereum();
  const walletClient = createWalletClient({ chain: giwaSepolia, transport: custom(injected) });
  const [account] = await walletClient.requestAddresses();
  const pool = { address: poolAddr as Address, abi: POOL_ABI } as const;
  // The batch's kemCiphertext was encapsulated to the bundled ARBITER_KEM_PK at
  // assemble time; before it leaves the machine, require the chain to vouch for
  // that key (design doc §4/§5) — a pre-KEM or foreign-keyed pool fails with a
  // readable error instead of an unlabeled revert / undecryptable envelope.
  let onchainKemPkHash: string | null;
  try {
    const epoch = await publicClient.readContract({ ...pool, functionName: "currentEpoch" });
    onchainKemPkHash = String(
      await publicClient.readContract({ ...pool, functionName: "arbiterKemPkHash", args: [epoch] }),
    );
  } catch (e) {
    if (!isViemPreKemProbeError(e) && !isPreKemProbeError(e)) throw e;
    onchainKemPkHash = null;
  }
  const kemGuard = arbiterKemPkGuardError(onchainKemPkHash);
  if (kemGuard) throw new Error(kemGuard);
  const hash = await walletClient.writeContract({
    ...pool,
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
    account,
    chain: giwaSepolia,
    // Pinned, never estimated: wallet-stack auto-estimation once overpaid ~1500x.
    gasPrice: GAS_PRICE,
  });
  await publicClient.waitForTransactionReceipt({ hash });
  return { txHash: hash, explorerUrl: explorerTxUrl(hash, explorerBase) };
}
