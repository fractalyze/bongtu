// Runnable bongtu indexer service (SPEC §6b): ingest -> mirror -> serve.
//
// Env:
//   RPC / GIWA_RPC / E2E_RPC   RPC endpoint (default anvil 127.0.0.1:8545)
//   POOL                       pool address (else deploy/addresses.<CHAIN_ID>.json)
//   CHAIN_ID                   chain id for the addresses file (default 91342)
//   START_BLOCK                first block to replay (default 0)
//   PORT                       HTTP port (default 8600)
//   POLL_MS                    incremental re-ingest interval (default 5000; 0 = off)
//   DATABASE_URL               REQUIRED — Postgres connection string (the indexer
//                              is Postgres-only; it refuses to boot without it)
//   LOG_CHUNK                  getLogs chunk size in blocks (default 50000)
//   AUTHORITY_KEY              arbiter PRIVATE key (bjj scalar) => ARBITER MODE:
//                              decrypt every op's authority envelope, build the
//                              note ledger, serve /notes + within-batch /path.
//                              UNSET => PUBLIC MODE (no /notes; batch /path 422s).
//
// Read-only on-chain: opens no wallet, sends no transactions. In arbiter mode it
// holds the arbiter private key in memory ONLY — never logged, never in a response.

import { resolveConfig, databaseUrlError } from "./chain.js";
import { Indexer } from "./ingest.js";
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
  const pollMs = process.env.POLL_MS !== undefined ? Number(process.env.POLL_MS) : 5000;

  // Mode is logged; the arbiter key and the DATABASE_URL (may carry a password)
  // are NEVER printed.
  const mode = cfg.authorityKey != null ? "ARBITER" : "public";
  console.log(`bongtu indexer: rpc=${cfg.rpc} pool=${cfg.pool} startBlock=${cfg.startBlock} mode=${mode} backend=postgres`);
  const ix = new Indexer(cfg);
  await ix.ingest();
  const hd = await ix.head();
  console.log(`ingested to head: root=${hd.root} nextLeafIndex=${hd.nextLeafIndex} events=${ix.store.allEvents().length} alarms=${ix.store.getAlarms().length}`);

  const api = await startApi(ix, port);
  const arbiterEndpoints = ix.arbiterMode ? " /notes?owner=" : "";
  console.log(`API listening on :${api.port} (GET /head /events /path/:i /alarms /health /nullifiers${arbiterEndpoints})`);

  // Incremental tail: the scheduler + retry/cursor policy live in Indexer
  // (pollOnce/startTailPolling); /health projects the recorded poll state.
  const stopTail = pollMs > 0 ? ix.startTailPolling(pollMs) : null;

  // Graceful shutdown: stop the tail, close the HTTP server, and end the Postgres
  // pool so in-flight clients drain instead of being severed. The unref'd failsafe
  // force-exits if any close hangs, so a SIGTERM always terminates the process.
  let closing = false;
  const shutdown = async (): Promise<void> => {
    if (closing) return;
    closing = true;
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
