// Runnable bongtu withdraw relayer — gas-sponsored withdraw submission.
//
// WHY THIS SERVICE CAN EXIST: the withdraw circuit binds the payout address into
// the proof (pub[26]), and the contract pays that address, never msg.sender. So
// ANYONE may submit a proven withdraw without being able to redirect it — the
// relayer sponsors gas and gains no custody. WITHDRAW-ONLY by design: transfers
// and deposits carry no proof-bound recipient, so relaying them would let the
// relayer redirect nothing but still spend its gas for someone else's account
// bookkeeping — there is no service there worth a key. (Full argument: relay.ts.)
//
// PoC scope: no fee model, no rate limiting, no queue — one tx at a time (each
// /relay awaits its receipt before responding). The institution box runs this
// next to the arbiter indexer.
//
// Env:
//   RPC             RPC endpoint (default anvil 127.0.0.1:8545)
//   POOL            pool address (else deploy/addresses.<CHAIN_ID>.json)
//   CHAIN_ID        chain id for the addresses file (default: the sdk CHAIN_ID)
//   PORT            HTTP port (default 8700)
//   SUBMITTER_KEY   REQUIRED — the funded EOA private key that signs every
//                   sponsored withdraw. Never logged, never in a response; the
//                   relayer refuses to boot without it (one clear line, same
//                   posture as the indexer's DATABASE_URL guard).

import { createPublicClient, createWalletClient, defineChain, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { resolveConfig, submitterKeyError } from "./config.js";
import { startApi } from "./server.js";
import type { RelayerChain } from "./relay.js";

async function main(): Promise<void> {
  // Fail-fast (no silent unsigned mode): refuse to boot without the submitter
  // key. One clear line, nonzero exit — the key itself is never echoed.
  const keyErr = submitterKeyError();
  if (keyErr) {
    console.error(keyErr);
    process.exit(1);
  }
  const cfg = resolveConfig();
  // A malformed key dies here with a SANITIZED line: the thrown error must not
  // echo the material (never logged, never in a response — header contract).
  const account = (() => {
    try {
      return privateKeyToAccount(cfg.submitterKey as `0x${string}`);
    } catch {
      console.error("FATAL: SUBMITTER_KEY is not a valid secp256k1 private key (expected 32 bytes of 0x-hex).");
      return process.exit(1);
    }
  })();
  // A minimal chain object over the configured id+rpc: the relayer serves anvil
  // in dev and the live chain in prod off the same two env vars, so it cannot
  // import the sdk's fixed liveChain.
  const chain = defineChain({
    id: cfg.chainId,
    name: `chain-${cfg.chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [cfg.rpc] } },
  });
  const transport = http(cfg.rpc);
  const deps: RelayerChain = {
    submitter: account.address,
    pool: cfg.pool,
    publicClient: createPublicClient({ chain, transport }),
    walletClient: createWalletClient({ account, chain, transport }),
  };

  // The submitter ADDRESS is logged (it is public on every tx anyway); the KEY
  // never is.
  console.log(`bongtu relayer: rpc=${cfg.rpc} pool=${cfg.pool} chainId=${cfg.chainId} submitter=${account.address}`);
  const api = await startApi(deps, cfg.port);
  console.log(`API listening on :${api.port} (POST /relay, GET /health) — withdraw-only, gas-sponsored`);

  const shutdownState = { closing: false };
  const shutdown = async (): Promise<void> => {
    if (shutdownState.closing) return;
    shutdownState.closing = true;
    setTimeout(() => process.exit(0), 3000).unref();
    try {
      await api.stop();
    } catch { /* already closing */ }
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

main().catch((e) => {
  console.error("relayer fatal:", e && e.stack ? e.stack : e);
  process.exit(1);
});
