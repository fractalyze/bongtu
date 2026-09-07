// The portalPriv (consumer receive) leg of the M0 DoD gate (e2e_orchestrator.ts
// calls it after the consumer leg) — the spec's unlinkability gate (R7) with
// the REAL services in the loop:
//
//   DEPLOY   a leg-owned enterprise stack + DepositPrivModule (registerModule
//            — modules are live immediately) + BOTH factories: the portal pair
//            (coexistence) and the PortalPrivFactory under test
//   SPAWN    the real apps/indexer (PUBLIC mode — the consumer posture) with
//            PORTAL_PRIV_FACTORY + PORTAL_OPERATOR_TOKEN set
//   REGISTER a v2 payment name: stealth meta + the consumer pair under one
//            owner signature
//   ISSUE    TWO pay-page issuances — the pay-web derivation called headlessly
//            (@bongtu/pay-web/pay): browser-side scalar, announce BEFORE
//            display, destination parity against the server recompute AND the
//            chain's addressOf
//   PAY      two plain ERC-20 transfers from TWO DISTINCT funded EOAs (all a
//            stock wallet can do)
//   GATE     the attributed work feed 401s without the operator token
//   SWEEP    apps/sweeper runOnce AS A LIBRARY in priv mode: depositPriv
//            proofs sealed to the registered consumer triple, submitted
//            through the PortalPrivFactory with the announcement tuple
//   ASSERT   R7: (a) the two destinations differ; (b) NEGATIVE GREP — neither
//            payment tx (calldata or logs), neither sweep tx calldata, nor the
//            public feed body carries the recipient's label or any registered
//            key; (c) the public projection serves no attribution field at
//            all; (d) after an indexer restart (boot ingest) both records flip
//            swept, the on-chain Announced events carry the exact issuance
//            tuples, and the recipient's SELF-SCAN discovers both payments as
//            unspent notes — chain + public endpoints only, no arbiter read
//            anywhere on this path.
//
// POLL_MS=0 (tail off) + restart is the portal leg's determinism recipe: all
// chain-derived state lands exactly at boot ingest, so every flip assertion is
// a statement, not a race.

import { spawn, type ChildProcess } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseAbiItem } from "viem";
import type { Address } from "viem";

import { packPubkey } from "@bongtu/core/pubkey";
import { portalSalt, scanStealthAnnouncement, stealthKeysFromScalars } from "@bongtu/core/stealth";
import {
  buildNameRegistrationV2,
  fetchUnswept,
  getPortalAnnouncements,
  registerName,
  resolveName,
  IndexerClient,
} from "@bongtu/core/indexerApi";
import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import { consumerRecipientOf, selfConsumerRecipient } from "@bongtu/client/consumer";
import { randField } from "@bongtu/client/spend";
import { EMPTY_SCAN_STATE, runSelfScan, type SelfScanState } from "@bongtu/client/selfscan";
import { initialState, runOnce, type SweeperChain, type SweeperDeps } from "@bongtu/sweeper/sweep";
import { makeCircuitProver } from "@bongtu/sweeper/prover";
import { issuePayment } from "@bongtu/pay-web/pay";

import { GATE_B, RPC, deploy, deployStack, ok, step } from "../live/lib/e2e_harness.js";
import { anvilChain, makeRig } from "../live/lib/viem_client.js";
import type { Contract, Rig } from "../live/lib/viem_client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // deploy/gates -> repo root

// The recipient: a full consumer wallet identity (the wallet's own derivation)
// plus a stealth meta pair — seeds/scalars disjoint from every other driver.
const RECIPIENT = deriveIdentityFromSignature("0x" + "c3".repeat(65));
const STEALTH_VIEW_SCALAR = 424242424242424242424n;
const STEALTH_SPEND_SCALAR = 535353535353535353535n;
const RECEIVE_NAME = "receive-payee";
const OPERATOR_TOKEN = "gate-operator-token";

// Two payments from two distinct senders (anvil's well-known funded keys #8/#9
// — never the orchestrator key, so the payers share nothing with the sweeper).
const PAYER_KEYS = [
  "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
  "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
];
const PAY_A = 641n;
const PAY_B = 883n;

const SWEPT_EVENT = parseAbiItem("event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount)");
const ANNOUNCED_EVENT = parseAbiItem("event Announced(bytes32 indexed salt, bytes32 ephemeralPub, uint8 viewTag)");

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

/** Case-insensitive substring check over hex/JSON haystacks. */
const contains = (haystack: string, needle: string): boolean =>
  haystack.toLowerCase().includes(needle.replace(/^0x/, "").toLowerCase());

export async function runPortalPrivLeg(rig: Rig): Promise<void> {
  step("PORTAL-PRIV: leg-owned stack + DepositPrivModule + both factories + public indexer");
  const databaseUrl = process.env.E2E_PORTAL_PRIV_DATABASE_URL || "";
  ok(databaseUrl !== "", "E2E_PORTAL_PRIV_DATABASE_URL is set (portalPriv leg is mandatory — no silent skip)");

  const { token, pool } = await deployStack(rig, {
    batchSize: GATE_B,
    authorityPublicKey: [101n, 202n], // enterprise epoch key — unused by consumer ops
    mintAmount: 1_000_000n,
  });
  const dpv = await deploy(rig, "DepositPrivVerifier", "DepositPrivVerifier");
  const depMod = await deploy(rig, "DepositPrivModule", "DepositPrivModule", [pool.address, dpv.address]);
  await pool.write("registerModule", [depMod.address]);
  ok((await pool.read("registeredModules", [depMod.address])) === true, "DepositPrivModule registered");
  // The depositor-facing portal pair coexists (R11's shape): the indexer runs
  // with BOTH factories configured, each product on its own contracts.
  const portalFactory = await deploy(rig, "PortalFactory", "PortalFactory", [rig.address]);
  const factory = await deploy(rig, "PortalPrivFactory", "PortalPrivFactory", [rig.address]);
  const initCodeHash = String(await factory.read("sweeperInitCodeHash"));
  console.log(`   pool=${pool.address} portalPrivFactory=${factory.address}`);

  const port = Number(process.env.E2E_PORTAL_PRIV_INDEXER_PORT || 8633);
  const indexerUrl = `http://127.0.0.1:${port}`;
  const indexerEnv = {
    RPC,
    POOL: String(pool.address),
    START_BLOCK: "0",
    DATABASE_URL: databaseUrl,
    PORTAL_FACTORY: String(portalFactory.address),
    PORTAL_PRIV_FACTORY: String(factory.address),
    PORTAL_OPERATOR_TOKEN: OPERATOR_TOKEN,
    PORT: String(port),
    POLL_MS: "0", // tail OFF — chain state lands at boot ingest (see header)
  };
  const child = { proc: spawnIndexer(indexerEnv) };
  try {
    await waitHealthy(indexerUrl);
    ok(true, `public indexer (PORTAL_PRIV_FACTORY + operator token) healthy on :${port}`);

    // ================== REGISTER (v2: meta + consumer pair) =================
    step("PORTAL-PRIV: register the v2 payment name (stealth meta + consumer pair)");
    const recipientCompressed = packPubkey(RECIPIENT.keypair.publicKey);
    const stealth = stealthKeysFromScalars(STEALTH_VIEW_SCALAR, STEALTH_SPEND_SCALAR);
    const pair = selfConsumerRecipient(RECIPIENT);
    await registerName(
      indexerUrl,
      buildNameRegistrationV2(
        RECEIVE_NAME,
        recipientCompressed,
        RECIPIENT.keypair.formattedPrivateKey,
        stealth.meta,
        { noteViewPub: pair.noteViewPub, kemEk: pair.kemEk },
      ),
    );

    // ============ ISSUE x2 (the pay page, called headlessly) ================
    step("PORTAL-PRIV: two pay-page issuances (browser derivation, announce-before-display)");
    const payDeps = {
      indexerUrl,
      portalPrivFactory: String(factory.address),
      sweeperInitCodeHash: initCodeHash,
    };
    const issuedA = await issuePayment(RECEIVE_NAME, payDeps);
    const issuedB = await issuePayment(RECEIVE_NAME, payDeps);
    ok(issuedA.destination.toLowerCase() !== issuedB.destination.toLowerCase(),
      "R7(a): the two issuances derived DISTINCT destinations");
    for (const issued of [issuedA, issuedB]) {
      const onChain = String(await factory.read("addressOf", [portalSalt(issued.stealthAddr)]));
      ok(onChain.toLowerCase() === issued.destination.toLowerCase(),
        "issued destination == portalPrivFactory.addressOf(portalSalt(stealthAddr)) on-chain");
      const rescan = scanStealthAnnouncement(STEALTH_VIEW_SCALAR, stealth.meta.spendPub, issued.ephemeralPub);
      ok(rescan.address.toLowerCase() === issued.stealthAddr.toLowerCase(),
        "recipient view key re-derives the announced stealth address from R alone");
    }

    // ============== PAY x2 (plain transfers, distinct EOAs) =================
    step(`PORTAL-PRIV: plain transfers ${PAY_A} + ${PAY_B} from two distinct sender EOAs`);
    const payments = [
      { issued: issuedA, amount: PAY_A },
      { issued: issuedB, amount: PAY_B },
    ];
    const paymentTxs: `0x${string}`[] = [];
    for (const [i, p] of payments.entries()) {
      const payer = makeRig({ chain: anvilChain(RPC), rpc: RPC, privateKey: PAYER_KEYS[i] });
      await token.write("transfer", [payer.address, p.amount]); // fund the payer
      const payerToken: Contract = payer.at(String(token.address), token.abi);
      const receipt = await payerToken.write("transfer", [p.issued.destination, p.amount]);
      paymentTxs.push(receipt.transactionHash);
    }

    // ==================== GATE (operator token, spec C3) ====================
    step("PORTAL-PRIV: the attributed work feed is operator-token gated");
    await fetchUnswept(indexerUrl).then(
      () => ok(false, "unswept without the operator token must 401"),
      (e) => ok(String(e).includes("401"), "unswept without the operator token -> 401"),
    );
    const unswept = await fetchUnswept(indexerUrl, -1, 5000, fetch, OPERATOR_TOKEN);
    ok(payments.every((p) => unswept.some((r) => r.destination.toLowerCase() === p.issued.destination.toLowerCase())),
      "both issuances on the token-authed work feed, attributed");

    // ================= SWEEP (receive-mode runOnce, library) ================
    step("PORTAL-PRIV: sweeper runOnce in priv mode (depositPriv, real CPU prover)");
    const poolBefore = BigInt(await token.read("balanceOf", [pool.address]));
    const chain: SweeperChain = {
      sweeper: rig.address,
      factory: String(factory.address),
      pool: String(pool.address),
      token: String(token.address),
      publicClient: rig.publicClient,
      walletClient: rig.walletClient,
    };
    const deps: SweeperDeps = {
      chain,
      fetchUnswept: () => fetchUnswept(indexerUrl, -1, 5000, fetch, OPERATOR_TOKEN),
      prove: makeCircuitProver(join(ROOT, "circuits", "out"), "depositPriv"),
      rand: randField,
      priv: {
        module: String(depMod.address),
        minSweep: 1n,
        resolveRecipient: async (name: string) => {
          const record = await resolveName(indexerUrl, name);
          if (!record) throw new Error(`name "${name}" not in the directory`);
          return consumerRecipientOf(record);
        },
      },
    };
    await runOnce(deps, initialState());
    const poolAfter = BigInt(await token.read("balanceOf", [pool.address]));
    ok(poolAfter - poolBefore === PAY_A + PAY_B,
      `both sweeps grew the pool by exactly the payments (${PAY_A} + ${PAY_B})`);
    for (const p of payments) {
      ok(BigInt(await token.read("balanceOf", [p.issued.destination])) === 0n,
        "priv destination emptied by the sweep");
    }

    // ============ ANNOUNCED events carry the exact issuance tuples ==========
    const announcedLogs = await rig.publicClient.getLogs({
      address: factory.address as Address,
      event: ANNOUNCED_EVENT,
      fromBlock: 0n,
    });
    ok(announcedLogs.length === 2, "factory emitted TWO Announced events (chain-only recovery path)");
    for (const p of payments) {
      const match = announcedLogs.find(
        (l) => String((l.args as { ephemeralPub: string }).ephemeralPub).toLowerCase() === p.issued.ephemeralPub.toLowerCase(),
      );
      ok(match !== undefined && Number((match.args as { viewTag: number }).viewTag) === p.issued.viewTag,
        "Announced carries this issuance's exact (ephemeralPub, viewTag)");
    }
    const sweptLogs = await rig.publicClient.getLogs({
      address: factory.address as Address, event: SWEPT_EVENT, fromBlock: 0n,
    });
    const sweepTxs = [...new Set(sweptLogs.map((l) => l.transactionHash))];

    // ================== R7(b): the NEGATIVE GREP ============================
    step("PORTAL-PRIV: negative grep — no recipient identity in payment/sweep txs or the public feed");
    // Everything the recipient registered — none of it may appear in the clear.
    const needles: [string, string][] = [
      ["label", RECEIVE_NAME],
      ["owner bjj pubkey", recipientCompressed],
      ["stealth viewPub", stealth.meta.viewPub],
      ["stealth spendPub", stealth.meta.spendPub],
      ["noteViewPub", pair.noteViewPub],
      ["kemEk", pair.kemEk],
    ];
    for (const [what, txs] of [["payment", paymentTxs], ["sweep", sweepTxs]] as const) {
      for (const hash of txs) {
        const tx = await rig.publicClient.getTransaction({ hash });
        const receipt = await rig.publicClient.getTransactionReceipt({ hash });
        const haystack = [tx.input, ...receipt.logs.map((l) => [l.data, ...l.topics].join(""))].join("");
        for (const [name, needle] of needles) {
          ok(!contains(haystack, needle), `${what} tx carries no ${name} in calldata/logs`);
        }
      }
    }
    const publicFeed = JSON.stringify(await getPortalAnnouncements(indexerUrl));
    for (const [name, needle] of needles) {
      ok(!contains(publicFeed, needle), `public announce feed carries no ${name}`);
    }
    ok(!publicFeed.includes('"name"') && !publicFeed.includes('"owner"'),
      "R7(c): public projection has no attribution field at all");

    // ============ FLIP + DISCOVERY (restart -> boot ingest) =================
    step("PORTAL-PRIV: restart indexer -> records flip swept; recipient self-scan finds both notes");
    await stopIndexer(child.proc);
    child.proc = spawnIndexer(indexerEnv);
    await waitHealthy(indexerUrl);

    const records = await getPortalAnnouncements(indexerUrl);
    for (const p of payments) {
      const rec = records.find((r) => r.stealthAddr === p.issued.stealthAddr.toLowerCase());
      ok(rec !== undefined && rec.swept === true && rec.sweptAmount === p.amount.toString(),
        `record flipped swept with the proof-bound amount (${p.amount})`);
    }
    const unsweptAfter = await fetchUnswept(indexerUrl, -1, 5000, fetch, OPERATOR_TOKEN);
    ok(!unsweptAfter.some((r) => payments.some((p) => r.stealthAddr === p.issued.stealthAddr.toLowerCase())),
      "both swept records left the work feed");

    // R7(d): the recipient's OWN scan — public endpoints, no arbiter anywhere.
    const io = new IndexerClient(indexerUrl);
    const scanned = await (async (): Promise<SelfScanState> => {
      const settled = { state: await runSelfScan(io, RECIPIENT, EMPTY_SCAN_STATE) };
      for (const _ of Array(60).keys()) {
        if (settled.state.pending.length === 0 && settled.state.notes.length >= 2) break;
        await new Promise((r) => setTimeout(r, 1000));
        settled.state = await runSelfScan(io, RECIPIENT, settled.state);
      }
      return settled.state;
    })();
    const unspentValues = scanned.notes.filter((n) => !n.spent).map((n) => n.value);
    ok(unspentValues.includes(PAY_A.toString()) && unspentValues.includes(PAY_B.toString()),
      `R7(d): self-scan discovered BOTH payments as unspent notes (${PAY_A}, ${PAY_B})`);
    const balance = scanned.notes.filter((n) => !n.spent).reduce((a, n) => a + BigInt(n.value), 0n);
    ok(balance === PAY_A + PAY_B, "self-scan balance == the two payments, shielded");
  } finally {
    await stopIndexer(child.proc);
  }
}
