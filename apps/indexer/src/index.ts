// Runnable bongtu indexer service (SPEC §6b): ingest -> mirror -> serve.
//
// Env:
//   RPC / GIWA_RPC / E2E_RPC   RPC endpoint (default anvil 127.0.0.1:8545)
//   POOL                       pool address (else deploy/addresses.<CHAIN_ID>.json)
//   CHAIN_ID                   chain id for the addresses file (default 91342)
//   START_BLOCK                first block to replay (default 0)
//   PORT                       HTTP port (default 8600)
//   POLL_MS                    incremental re-ingest interval (default 5000; 0 = off)
//   AUTHORITY_KEY              arbiter PRIVATE key (bjj scalar) => ARBITER MODE:
//                              decrypt every op's authority envelope, build the
//                              note ledger, serve /notes + within-batch /path.
//                              UNSET => PUBLIC MODE (no /notes; batch /path 422s).
//
// Read-only on-chain: opens no wallet, sends no transactions. In arbiter mode it
// holds the arbiter private key in memory ONLY — never logged, never in a response.

import { resolveConfig } from "./chain.js";
import { Indexer } from "./ingest.js";
import { startApi } from "./api/router.js";

async function main(): Promise<void> {
  const cfg = resolveConfig();
  const port = Number(process.env.PORT || 8600);
  const pollMs = process.env.POLL_MS !== undefined ? Number(process.env.POLL_MS) : 5000;

  // Mode is logged; the key itself is NEVER printed.
  const mode = cfg.authorityKey != null ? "ARBITER" : "public";
  console.log(`bongtu indexer: rpc=${cfg.rpc} pool=${cfg.pool} startBlock=${cfg.startBlock} mode=${mode}`);
  const ix = new Indexer(cfg);
  await ix.ingest();
  const hd = await ix.head();
  console.log(`ingested to head: root=${hd.root} nextLeafIndex=${hd.nextLeafIndex} events=${ix.store.allEvents().length} alarms=${ix.store.getAlarms().length}`);

  const api = await startApi(ix, port);
  const arbiterEndpoints = ix.arbiterMode ? " /notes?owner=" : "";
  console.log(`API listening on :${api.port} (GET /head /events /path/:i /alarms /health /nullifiers${arbiterEndpoints})`);

  // Incremental tail: the scheduler + retry/cursor policy live in Indexer
  // (pollOnce/startTailPolling); /health projects the recorded poll state.
  if (pollMs > 0) ix.startTailPolling(pollMs);
}

main().catch((e) => {
  console.error("indexer fatal:", e && e.stack ? e.stack : e);
  process.exit(1);
});
