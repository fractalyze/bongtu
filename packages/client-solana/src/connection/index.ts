// The ONE stable public subpath (@bongtu/client-solana/connection) — the
// SolanaConnection shape, the cluster guard, the RPC reads, the key-derivation
// signing edge (edge.ts), and the keypair-backed headless connection
// (keypair.ts). The wallet failure copy stays the engine's rail seam
// (@bongtu/client/rail) — re-exported here so the wallet's words remain
// importable beside the edges that throw them, mirroring client-evm.
export * from "./edge.js";
export * from "./keypair.js";
export { WALLET_FAILURE_COPY, walletErrorMessage } from "@bongtu/client/rail";
