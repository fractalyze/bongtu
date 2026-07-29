// GIWA Sepolia as a viem chain, plus the pinned gas price every tx sends with.
// Derived field-for-field from @bongtu/core/network (the ONE home of the chain
// facts, equality-tested against deploy/addresses.91342.json) so a chain move
// cannot fork the wallet's idea of the network from the sdk's.

import { defineChain, parseGwei } from "viem";
import { CHAIN_ID, EXPLORER_BASE, GIWA_GAS_FLOOR_GWEI, RPC_URL } from "@bongtu/core/network";

/** The chain object viem/wagmi consume — also what wallet_addEthereumChain
 *  registers when a wallet has never seen GIWA (connection.ts ensureChain). */
export const giwaSepolia = defineChain({
  id: CHAIN_ID,
  name: "GIWA Sepolia (Testnet)",
  nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: "GIWA Sepolia Blockscout", url: EXPLORER_BASE } },
  testnet: true,
});

/** The pinned per-tx gas price (wei). GIWA wants ~0.001 gwei and wallet-stack
 *  auto-estimation historically overpaid ~1500x (drained the faucet grant), so
 *  EVERY write pins this instead of estimating (@bongtu/core GIWA_GAS_FLOOR_GWEI). */
export const GAS_PRICE = parseGwei(GIWA_GAS_FLOOR_GWEI);
