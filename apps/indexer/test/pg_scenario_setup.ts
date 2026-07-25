// Deploy + drive the shared indexer scenario on the live anvil, then write the
// fixtures the Postgres integration test needs (pool address, arbiter key, the
// recipient keys/amounts, head root, nextLeafIndex). The indexer process under
// test then ingests the SAME pool from env — this script only sets the chain up
// and records what the running indexer must reproduce.
//
//   node --import tsx test/pg_scenario_setup.ts <fixtures.json>
//
// Reuses runScenario() (the same deposit → disburse(16) → transfer → withdraw →
// tampered-disburse cycle the conformance gate drives); proving is CPU snarkjs.

import { writeFileSync } from "node:fs";
import { runScenario } from "./scenario.js";

async function main(): Promise<void> {
  const out = process.argv[2];
  if (!out) throw new Error("usage: pg_scenario_setup.ts <fixtures.json>");
  const sc = await runScenario();
  writeFileSync(out, JSON.stringify(sc, null, 2));
  console.log(`SCENARIO_READY pool=${sc.poolAddr} nextLeafIndex=${sc.nextLeafIndex} headRoot=${sc.headRoot}`);
  // The ethers v5 JsonRpcProvider keeps open handles (a keep-alive socket) that
  // would otherwise pin the event loop open — exit explicitly so the shell driver
  // does not block on a process that has already done its work.
  process.exit(0);
}

main().catch((e) => {
  console.error("SCENARIO SETUP ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
