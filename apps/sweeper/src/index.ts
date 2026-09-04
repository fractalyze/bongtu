// Runnable bongtu portal sweeper — the Slice ⑤ U-P3 operator bot.
//
// WHY THIS SERVICE EXISTS: a portal payer (a CEX, a plain wallet) can only do a
// plain ERC-20 transfer to the CREATE2 destination the resolver issued — it can
// never call a contract. SOMEONE must later deploy the PortalSweeper there and
// shield the balance into the pool, and PortalFactory.sweep is onlyOwner (the
// recorded Slice ⑤ trust concession: the deposit proof has no owner binding, so
// without the gate anyone could mint the notes to themselves). This bot IS that
// owner: it watches the indexer's unswept feed, and for each funded destination
// builds a deposit minting the FULL balance to the announced recipient's bjj
// key, proves it on CPU, and sweeps.
//
// PoC boundaries (stated, not hidden): NO batching (one record in flight at a
// time), NO fee (the bot eats the gas), FULL-BALANCE sweeps only (pub[0] = the
// pre-prove balance; a mid-proof payment's remainder is re-swept next round),
// and retries BY RESCAN (no queue/backoff — the indexer flips `swept` off the
// Swept event, so an unswept record simply comes around again each POLL_MS).
//
// Env:
//   SWEEPER_KEY   REQUIRED — the factory-owner EOA private key that signs every
//                 sweep. Never logged, never in a response; the sweeper refuses
//                 to boot without it (one clear line, the relayer posture).
//   INDEXER_URL   REQUIRED — the indexer serving GET /portal/unswept.
//   RPC           RPC endpoint (default anvil 127.0.0.1:8545)
//   POOL          pool address (else deploy/addresses.<CHAIN_ID>.json `pool`)
//   FACTORY       PortalFactory address (else the record's `portalFactory`)
//   TOKEN         the swept ERC-20 (default @bongtu/core/network TOKEN_ADDRESS)
//   CHAIN_ID      chain id for the addresses file (default: the sdk CHAIN_ID)
//   PORT          HTTP port for GET /health (default 8710)
//   POLL_MS       rescan period in ms (default 15000)
//   CIRCUITS_OUT  deposit zkey/wasm directory (default <repo>/circuits/out)

import { createPublicClient, createWalletClient, defineChain, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { IndexerClient } from "@bongtu/core/indexerApi";
import { randField } from "@bongtu/client/spend";

import { bootError, resolveConfig } from "./config.js";
import { makeDepositProver } from "./prover.js";
import { initialState, runOnce, type SweeperChain, type SweeperDeps } from "./sweep.js";
import { startApi } from "./server.js";

async function main(): Promise<void> {
  // Fail-fast (no silent idle mode): refuse to boot without the sweep key or a
  // work source. One clear line, nonzero exit — the key itself is never echoed.
  const bootErr = bootError();
  if (bootErr) {
    console.error(bootErr);
    process.exit(1);
  }
  const cfg = resolveConfig();
  // A malformed key dies here with a SANITIZED line: the thrown error must not
  // echo the material (never logged, never in a response — header contract).
  const account = (() => {
    try {
      return privateKeyToAccount(cfg.sweeperKey as `0x${string}`);
    } catch {
      console.error("FATAL: SWEEPER_KEY is not a valid secp256k1 private key (expected 32 bytes of 0x-hex).");
      return process.exit(1);
    }
  })();
  // A minimal chain object over the configured id+rpc: the sweeper serves anvil
  // in dev and the live chain in prod off the same two env vars (the relayer's
  // defineChain rationale — it cannot import the sdk's fixed liveChain).
  const chainDef = defineChain({
    id: cfg.chainId,
    name: `chain-${cfg.chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [cfg.rpc] } },
  });
  const transport = http(cfg.rpc);
  const chain: SweeperChain = {
    sweeper: account.address,
    factory: cfg.factory,
    pool: cfg.pool,
    token: cfg.token,
    publicClient: createPublicClient({ chain: chainDef, transport }),
    walletClient: createWalletClient({ account, chain: chainDef, transport }),
  };
  // The bound client's tear-off IS the deps entry — arrow properties keep their
  // instance, and the free-function defaults (cursor -1, 5000 cap) still apply.
  const indexer = new IndexerClient(cfg.indexerUrl);
  const deps: SweeperDeps = {
    chain,
    fetchUnswept: indexer.unswept,
    prove: makeDepositProver(cfg.circuitsOut),
    rand: randField,
  };
  const state = initialState();

  // The sweeper ADDRESS is logged (it is public on every tx anyway); the KEY
  // never is.
  console.log(
    `bongtu sweeper: rpc=${cfg.rpc} factory=${cfg.factory} pool=${cfg.pool} token=${cfg.token} ` +
      `indexer=${cfg.indexerUrl} chainId=${cfg.chainId} pollMs=${cfg.pollMs} sweeper=${account.address}`,
  );
  const api = await startApi(chain, state, cfg.port);
  console.log(`API listening on :${api.port} (GET /health) — portal sweeps: full-balance, no fee, retries by rescan`);

  // The poll loop: setTimeout AFTER each round completes (never setInterval),
  // so rounds — like records inside a round — are strictly one in flight.
  const loop = { timer: null as NodeJS.Timeout | null, closing: false };
  const tick = async (): Promise<void> => {
    try {
      await runOnce(deps, state);
    } catch (e) {
      // Message only, never the raw object/stack — the log surface stays clean
      // of anything that could carry material.
      console.error(`sweep round failed: ${(e as Error).message}`);
    }
    if (!loop.closing) loop.timer = setTimeout(() => void tick(), cfg.pollMs);
  };
  void tick();

  const shutdown = async (): Promise<void> => {
    if (loop.closing) return;
    loop.closing = true;
    if (loop.timer) clearTimeout(loop.timer);
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
  console.error(`sweeper fatal: ${(e as Error).message ?? e}`);
  process.exit(1);
});
