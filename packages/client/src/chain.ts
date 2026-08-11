// The live deployment's chain as a viem object, plus the parsed gas pin.
// Derived field-for-field from @bongtu/core/network (the ONE home of the chain
// facts, equality-tested against the deploy record) so a chain move cannot fork
// the wallet's idea of the network from the sdk's — including the chain's NAME,
// which is a single string there rather than a literal repeated per screen.

import { defineChain } from "viem";
import {
  CHAIN_ID,
  CHAIN_NAME,
  EXPLORER_BASE,
  NATIVE_CURRENCY,
  RPC_URL,
} from "@bongtu/core/network";

/** The chain object viem/wagmi consume — also what wallet_addEthereumChain
 *  registers when a wallet has never seen this chain (connection.ts ensureChain). */
export const liveChain = defineChain({
  id: CHAIN_ID,
  name: CHAIN_NAME,
  nativeCurrency: NATIVE_CURRENCY,
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: `${CHAIN_NAME} Explorer`, url: EXPLORER_BASE } },
  testnet: true,
});
