// The Slice ⑤ U-P4 portal-deposit leg of the M0 DoD gate (e2e_orchestrator.ts
// calls it after the spend cycle) — the anvil twin of chains/evm/test/Portal.t.sol
// with the REAL services in the loop instead of fixtures:
//
//   DEPLOY   PortalFactory on the gate anvil (owner = the orchestrator key,
//            which therefore IS the sweeper bot key)
//   SPAWN    the real apps/indexer service (arbiter mode, PORTAL_FACTORY set)
//            against the gate chain + the gate's Postgres (E2E_DATABASE_URL)
//   ISSUE    register a payment name for a fresh recipient identity, then
//            POST /pay/{name} — assert the issued destination equals
//            factory.addressOf(portalSalt(stealthAddr)) ON-CHAIN, and that the
//            recipient's view key re-derives the announcement
//   PAY      a plain ERC-20 transfer to the destination (all a CEX can do)
//   SWEEP    apps/sweeper `runOnce` AS A LIBRARY with real deps — the gate
//            anvil RPC, the spawned indexer's /portal/unswept feed, and the
//            CPU snarkjs deposit prover — asserting the pool grew by exactly
//            the payment
//   RE-SWEEP a SECOND payment to the SAME destination + a second runOnce: the
//            factory must skip the CREATE2 (sweeper already deployed) and
//            sweep again (Portal.t.sol's re-sweep flow, now end to end)
//   FLIP     restart the indexer (its tail is off — POLL_MS=0 — so Swept marks
//            land exactly when the leg says: at boot ingest), then assert the
//            record flipped swept with the FIRST sweep's txHash (markSwept is
//            flip-once) and that the recipient's signed /notes carries BOTH
//            swept amounts as unspent notes owned by the recipient key
//
// POLL_MS=0 is load-bearing, not a convenience: with the tail off, the record
// stays on /portal/unswept between the two payments, which is what lets the
// second runOnce exercise the re-sweep path deterministically (a live tail
// would race the multi-second proof and flip the record mid-leg).
//
// The KEM draw is injected: the gate pool's epoch-0 arbiter KEM key is the
// FIXTURE keypair (deployStack default), while the sweeper's default
// freshKemMaterial encapsulates to the LIVE ARBITER_KEM_PK — correct in
// production, undecryptable by the gate's fixture-keyed arbiter indexer. The
// harness kemDraw (fixture-keyed, label-derived) stands in through the
// SweeperDeps seam.

import { spawn, type ChildProcess } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseAbiItem } from "viem";
import type { Address } from "viem";

import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { portalSalt, scanStealthAnnouncement, stealthKeysFromScalars } from "@bongtu/core/stealth";
import {
  buildNameRegistration,
  buildNotesUrl,
  fetchNotes,
  fetchUnswept,
  getPortalAnnouncements,
  payPortal,
  registerName,
} from "@bongtu/core/indexerApi";
import { randField } from "@bongtu/client/spend";
import type { KemMaterial } from "@bongtu/client/spend";
import { initialState, runOnce, type SweeperChain, type SweeperDeps } from "@bongtu/sweeper/sweep";
import { makeDepositProver } from "@bongtu/sweeper/prover";

import { AUTHORITY_KEM, FIXTURE_ARBITER_SCALAR } from "../../circuits/fixtures/fixture_lib.js";
import { RPC, deploy, kemCtHex, kemDraw, ok, step } from "../live/lib/e2e_harness.js";
import type { Contract, Rig } from "../live/lib/viem_client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // deploy/gates -> repo root

// The fresh recipient identity — scalars disjoint from every harness actor
// (EMPLOYER 111…, PAYEE 222…, arbiter 555…, batch recipients 2000000011+…).
const RECIPIENT = deriveKeypair(999999999999999999999999n);
const STEALTH_VIEW_SCALAR = 123456789123456789123n;
const STEALTH_SPEND_SCALAR = 987654321987654321987n;
const PORTAL_NAME = "portal-payee";

// The two plain payments (raw token units; the employer wallet holds V*1000).
const PAY_1 = 777n;
const PAY_2 = 555n;

const SWEPT_EVENT = parseAbiItem("event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount)");

/** Spawn the REAL indexer service (apps/indexer) against the gate chain. */
function spawnIndexer(env: Record<string, string>): ChildProcess {
  const proc = spawn(process.execPath, ["--import", "tsx", "apps/indexer/src/index.ts"], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const relay = (data: unknown): void => {
    process.stdout.write(String(data).replace(/^(?=.)/gm, "   [indexer] "));
  };
  proc.stdout?.on("data", relay);
  proc.stderr?.on("data", relay);
  return proc;
}

async function waitHealthy(indexerUrl: string): Promise<void> {
  for (const _ of Array(240).keys()) {
    const up = await fetch(`${indexerUrl}/health`).then((r) => r.ok, () => false);
    if (up) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`indexer did not become healthy at ${indexerUrl}`);
}

function stopIndexer(proc: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (proc.exitCode !== null) return resolve();
    proc.once("exit", () => resolve());
    proc.kill("SIGTERM");
    setTimeout(() => proc.kill("SIGKILL"), 8000).unref(); // the service's own failsafe is 3s
  });
}

export async function runPortalLeg(rig: Rig, pool: Contract, token: Contract): Promise<void> {
  step("PORTAL (Slice ⑤): factory deploy + real indexer, arbiter mode, PORTAL_FACTORY set");
  const databaseUrl = process.env.E2E_DATABASE_URL || "";
  // Throws when unset (ok() throws on failure): a missing Postgres fails the
  // gate loudly — the portal leg is part of the DoD and must never be skipped
  // silently (e2e_m0.sh provisions the database).
  ok(databaseUrl !== "", "E2E_DATABASE_URL is set (portal leg is mandatory — no silent skip)");

  const factory = await deploy(rig, "PortalFactory", "PortalFactory", [rig.address]);
  ok(String(await factory.read("owner")).toLowerCase() === rig.address.toLowerCase(),
    "PortalFactory owner == the orchestrator key (the gate's sweeper bot)");
  console.log(`   factory=${factory.address}`);

  const port = Number(process.env.E2E_PORTAL_INDEXER_PORT || 8631);
  const indexerUrl = `http://127.0.0.1:${port}`;
  const indexerEnv = {
    RPC,
    POOL: String(pool.address),
    START_BLOCK: "0",
    DATABASE_URL: databaseUrl,
    PORTAL_FACTORY: String(factory.address),
    AUTHORITY_KEY: FIXTURE_ARBITER_SCALAR.toString(),
    AUTHORITY_KEM_KEY: Buffer.from(AUTHORITY_KEM.secretKey).toString("hex"),
    PORT: String(port),
    POLL_MS: "0", // tail OFF — see the module header (deterministic re-sweep)
  };
  const child = { proc: spawnIndexer(indexerEnv) };
  try {
    await waitHealthy(indexerUrl);
    ok(true, `arbiter indexer (PORTAL_FACTORY set) healthy on :${port}`);

    // ======================= ISSUE (register -> /pay) =======================
    step("PORTAL: register recipient name -> POST /pay -> on-chain destination parity");
    const recipientCompressed = packPubkey(RECIPIENT.publicKey);
    const stealth = stealthKeysFromScalars(STEALTH_VIEW_SCALAR, STEALTH_SPEND_SCALAR);
    await registerName(
      indexerUrl,
      buildNameRegistration(PORTAL_NAME, recipientCompressed, RECIPIENT.formattedPrivateKey, stealth.meta),
    );
    const issued = await payPortal(indexerUrl, PORTAL_NAME);
    ok(issued.factory.toLowerCase() === String(factory.address).toLowerCase(),
      "issuance names the configured PortalFactory");
    const onChain = String(await factory.read("addressOf", [portalSalt(issued.stealthAddr)]));
    ok(onChain.toLowerCase() === issued.destination.toLowerCase(),
      "issued destination == factory.addressOf(portalSalt(stealthAddr)) on-chain");
    const rescan = scanStealthAnnouncement(STEALTH_VIEW_SCALAR, stealth.meta.spendPub, issued.ephemeralPub);
    ok(rescan.address.toLowerCase() === issued.stealthAddr.toLowerCase(),
      "recipient view key re-derives the announced stealth address from R alone");
    ok(rescan.viewTag === issued.viewTag, "announcement viewTag matches the recipient's re-derivation");

    // ================= PAY (plain transfer) -> SWEEP (runOnce) ==============
    step(`PORTAL: plain ERC-20 transfer of ${PAY_1} -> sweeper runOnce (library, real CPU prover)`);
    const poolBefore = BigInt(await token.read("balanceOf", [pool.address]));
    await token.write("transfer", [issued.destination, PAY_1]);

    const chain: SweeperChain = {
      sweeper: rig.address,
      factory: String(factory.address),
      pool: String(pool.address),
      token: String(token.address),
      publicClient: rig.publicClient,
      walletClient: rig.walletClient,
    };
    const kemSeq = { n: 0 };
    const deps: SweeperDeps = {
      chain,
      fetchUnswept: () => fetchUnswept(indexerUrl),
      prove: makeDepositProver(join(ROOT, "circuits", "out")),
      rand: randField,
      // fixture-keyed KEM encapsulation — see the module header for why the
      // sweeper's production default (live ARBITER_KEM_PK) is wrong HERE.
      drawKem: (): KemMaterial => {
        const draw = kemDraw(`m0/portal/${kemSeq.n++}`);
        return {
          kemSs: [draw.kemSs[0].toString(), draw.kemSs[1].toString()],
          kemCiphertext: kemCtHex(draw.kemCiphertext),
        };
      },
    };
    const state = initialState();
    await runOnce(deps, state);
    const afterFirst = BigInt(await token.read("balanceOf", [pool.address]));
    ok(afterFirst - poolBefore === PAY_1, `first sweep grew the pool by exactly the payment (${PAY_1})`);
    ok(BigInt(await token.read("balanceOf", [issued.destination])) === 0n,
      "portal destination emptied by the sweep");
    const code = await rig.publicClient.getCode({ address: issued.destination as Address });
    ok(typeof code === "string" && code.length > 2, "PortalSweeper deployed at the CREATE2 destination");

    // =================== RE-SWEEP (second payment, same dest) ===============
    step(`PORTAL: second payment of ${PAY_2} to the SAME destination -> second runOnce re-sweeps`);
    await token.write("transfer", [issued.destination, PAY_2]);
    const unswept = await fetchUnswept(indexerUrl);
    ok(unswept.some((r) => r.destination.toLowerCase() === issued.destination.toLowerCase()),
      "record still on /portal/unswept before the re-sweep (tail off — rescan IS the retry queue)");
    await runOnce(deps, state);
    const afterSecond = BigInt(await token.read("balanceOf", [pool.address]));
    ok(afterSecond - afterFirst === PAY_2, `re-sweep grew the pool by exactly the second payment (${PAY_2})`);

    const sweptLogs = await rig.publicClient.getLogs({
      address: factory.address as Address,
      event: SWEPT_EVENT,
      fromBlock: 0n,
    });
    ok(sweptLogs.length === 2, "factory emitted TWO Swept events (deploy-and-sweep, then re-sweep)");
    const amounts = sweptLogs.map((l) => (l.args as { amount: bigint }).amount);
    ok(amounts[0] === PAY_1 && amounts[1] === PAY_2,
      `Swept amounts are the proof-bound payments in order (${PAY_1}, ${PAY_2})`);
    const firstSweepTx = sweptLogs[0].transactionHash;

    // ============ FLIP (restart -> boot ingest catches both Swept) ==========
    step("PORTAL: restart indexer -> record flipped swept; /notes carries both notes");
    await stopIndexer(child.proc);
    child.proc = spawnIndexer(indexerEnv);
    await waitHealthy(indexerUrl);

    const records = await getPortalAnnouncements(indexerUrl);
    const record = records.find((r) => r.stealthAddr === issued.stealthAddr.toLowerCase());
    ok(record !== undefined, "issuance record survived the restart (Postgres write-through)");
    ok(record?.swept === true, "indexer record flipped swept off the factory's Swept event");
    ok(record?.sweptTxHash === firstSweepTx,
      "sweptTxHash == the FIRST sweep tx (markSwept is flip-once; the re-sweep no-ops the mark)");
    ok(record?.sweptAmount === PAY_1.toString(), "sweptAmount == the first proof-bound payment");
    const unsweptAfter = await fetchUnswept(indexerUrl);
    ok(!unsweptAfter.some((r) => r.stealthAddr === issued.stealthAddr.toLowerCase()),
      "swept record left the /portal/unswept work feed");

    const notes = await fetchNotes(
      buildNotesUrl(indexerUrl, recipientCompressed, RECIPIENT.formattedPrivateKey),
    );
    const unspentValues = notes.filter((n) => !n.spent).map((n) => n.value);
    ok(unspentValues.includes(PAY_1.toString()) && unspentValues.includes(PAY_2.toString()),
      `recipient /notes carries BOTH swept amounts (${PAY_1}, ${PAY_2}) as unspent notes`);
    ok(
      notes.every(
        (n) =>
          n.owner[0] === RECIPIENT.publicKey[0].toString() &&
          n.owner[1] === RECIPIENT.publicKey[1].toString(),
      ),
      "every recovered note is owned by the recipient's bjj key",
    );
  } finally {
    await stopIndexer(child.proc);
  }
}
