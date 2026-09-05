// Runnable bongtu indexer service (SPEC §6b): ingest -> mirror -> serve.
//
// Env:
//   RPC / LIVE_RPC / E2E_RPC   RPC endpoint (default anvil 127.0.0.1:8545)
//   POOL                       pool address (else deploy/addresses.<CHAIN_ID>.json)
//   CHAIN_ID                   chain id for the addresses file (default: the sdk
//                              CHAIN_ID — @bongtu/core/network, the one home)
//   START_BLOCK                first block to replay (default 0)
//   PORT                       HTTP port (default 8600)
//   POLL_MS                    incremental re-ingest interval (default 3000; 0 = off)
//   DATABASE_URL               REQUIRED — Postgres connection string (the indexer
//                              is Postgres-only; it refuses to boot without it)
//   LOG_CHUNK                  getLogs chunk size in blocks (default 50000)
//   KEM_GRACE_SECONDS          seconds an incomplete consumer-disburse chunk
//                              set reads kem-"pending" before kem-"withheld"
//                              (default 3600; parsed once at boot — garbage
//                              refuses to boot)
//   PORTAL_FACTORY             PortalFactory address => portal deposits live:
//                              POST /pay/{name} issues stealth destinations and
//                              ingest scans the factory's Swept logs. UNSET =>
//                              the /pay + /portal routes 404 (one boot line
//                              says so).
//   AUTHORITY_KEY              arbiter PRIVATE key (bjj scalar) => ARBITER MODE:
//                              decrypt every op's authority envelope, build the
//                              note ledger, serve /notes + within-batch /path.
//                              UNSET => PUBLIC MODE (no /notes; batch /path 422s).
//   AUTHORITY_KEM_KEY          arbiter ML-KEM-768 decapsulation key (hex) — the
//                              PQ half of the hybrid envelope. REQUIRED in
//                              arbiter mode once the pool is in a KEM epoch
//                              (the boot guard refuses to serve without it).
//                              Never logged, never in a response.
//   TOKEN_SECRET               HMAC secret for /auth view tokens (arbiter mode).
//                              Generated per boot when absent (warned: issued
//                              tokens then reset on restart).
//   PUBLIC_URL                 comma-separated origin(s) clients reach this
//                              indexer on — what /auth signatures are bound to.
//                              Behind the wallet's same-origin /indexer proxy that
//                              is the WALLET's origin, not the indexer's; getting
//                              it wrong makes every login fall back to the
//                              tokenless (no-persistence) path. Defaults to the
//                              loopback listen address.
//
// Read-only on-chain: opens no wallet, sends no transactions. In arbiter mode it
// holds the arbiter private key in memory ONLY — never logged, never in a response.

import { resolveConfig, databaseUrlError } from "./chain.js";
import { Indexer } from "./ingest.js";
import { SolanaIndexer } from "./solana/ingest.js";
import { SolanaRpcIo, base58ToHex } from "./solana/rpc.js";
import { startApi } from "./api/router.js";

async function main(): Promise<void> {
  // Postgres-only (U-I4): refuse to boot without DATABASE_URL — no silent
  // in-memory fallback. One clear line, nonzero exit.
  const dbErr = databaseUrlError();
  if (dbErr) {
    console.error(dbErr);
    process.exit(1);
  }
  const cfg = resolveConfig();
  const port = Number(process.env.PORT || 8600);
  const pollMs = process.env.POLL_MS !== undefined ? Number(process.env.POLL_MS) : 3000;

  // Mode is logged; the arbiter key and the DATABASE_URL (may carry a password)
  // are NEVER printed.
  const mode = cfg.authorityKey != null ? "ARBITER" : "public";
  console.log(
    cfg.solana
      ? `bongtu indexer: solana rpc=${cfg.solana.rpc} program=${cfg.solana.programId} mode=${mode} backend=postgres`
      : `bongtu indexer: rpc=${cfg.rpc} pool=${cfg.pool} startBlock=${cfg.startBlock} mode=${mode} backend=postgres`,
  );
  // One line either way: a missing PORTAL_FACTORY is a configuration CHOICE the
  // operator should be able to read off the boot log, not discover via a 404.
  console.log(
    cfg.portalFactory
      ? `portal deposits: factory=${cfg.portalFactory} (POST /pay/{name}, /portal/*)`
      : "portal deposits not configured (PORTAL_FACTORY unset) — POST /pay/{name} and /portal/* will 404",
  );
  // Backend selection is CONFIG, not code paths in routes: both classes serve
  // the identical read model, so everything below this line is backend-blind.
  const ix = cfg.solana
    ? new SolanaIndexer(cfg, new SolanaRpcIo(cfg.solana), base58ToHex(cfg.solana.programId))
    : new Indexer(cfg);
  // KEM boot guard (pq-envelope-design.md §7): a KEM-epoch pool served by a
  // V1-ABI build or a KEM-keyless arbiter fails SILENTLY (envelopes skipped /
  // undecryptable while the tree mirror stays green) — refuse to serve instead.
  const kemErr = await ix.kemBootGuard();
  if (kemErr) {
    console.error(kemErr);
    process.exit(1);
  }
  await ix.ingest();
  const hd = await ix.head();
  console.log(`ingested to head: root=${hd.root} nextLeafIndex=${hd.nextLeafIndex} events=${ix.store.allEvents().length} alarms=${ix.store.getAlarms().length}`);

  const api = await startApi(ix, port);
  const arbiterEndpoints = ix.arbiterMode ? " /notes?owner= /history?owner= /auth" : "";
  console.log(`API listening on :${api.port} (GET /head /events /path/:i /alarms /health /nullifiers${arbiterEndpoints})`);
  if (ix.arbiterMode) {
    // Printed because a PUBLIC_URL that does not match how wallets actually reach
    // this indexer degrades logins silently (tokenless, no persistence).
    console.log(`view-token origins (PUBLIC_URL): ${api.publicUrls.join(", ")}`);
  }

  // Incremental tail: the scheduler + retry/cursor policy live in Indexer
  // (pollOnce/startTailPolling); /health projects the recorded poll state.
  const stopTail = pollMs > 0 ? ix.startTailPolling(pollMs) : null;

  // Graceful shutdown: stop the tail, close the HTTP server, and end the Postgres
  // pool so in-flight clients drain instead of being severed. The unref'd failsafe
  // force-exits if any close hangs, so a SIGTERM always terminates the process.
  const shutdownState = { closing: false };
  const shutdown = async (): Promise<void> => {
    if (shutdownState.closing) return;
    shutdownState.closing = true;
    setTimeout(() => process.exit(0), 3000).unref();
    stopTail?.();
    try {
      await api.stop();
    } catch { /* already closing */ }
    try {
      await ix.close();
    } catch { /* pool already gone */ }
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

main().catch((e) => {
  console.error("indexer fatal:", e && e.stack ? e.stack : e);
  process.exit(1);
});
