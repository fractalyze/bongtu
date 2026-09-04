// The home of `Connection` — the one shape every other module works against
// (SPEC §6/§7) — and everything that operates ON a live one over viem: the
// deterministic eth_signTypedData_v4 signature the KDF consumes (derive.ts),
// the chain guard, the pool-KEM-epoch guard, and the proof/token submits + reads.
// How a browser REACHES a wallet (wagmi, EIP-6963, WalletConnect) is the app's
// business: apps/wallet-web/src/lib/wagmi.ts turns whatever wagmi connected into
// the `Connection` this module consumes. Everything here is wallet-library-free
// and gated headlessly: the account-watch sequences in this package's suite
// (test/accountWatch.test.ts), the submit/guard paths over fake EIP-1193
// transports in apps/wallet-web/test/connection.test.ts — that file also gates
// the app's wagmi half, so it stays where both subjects live.
// This file stitches the split module back into the ONE stable public subpath
// (@bongtu/client/connection); the implementation lives in the sibling parts.
export * from "./walletEdge.js";
export * from "./poolWrites.js";

