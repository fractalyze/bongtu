// The payment-name resolution leg of the M0 DoD gate (e2e_orchestrator.ts
// calls it after the portalPriv leg) — the name front door's gate (SPEC:
// payment-name R1-R6, R13) with the REAL services in the loop:
//
//   DEPLOY   a leg-owned stack + DepositPrivModule + PortalPrivFactory +
//            PortalPrivResolver (owner-set gateway signer + URL template)
//   SPAWN    the real apps/indexer with the CCIP gateway configured
//            (ENS_RESOLVER + ENS_GATEWAY_KEY + ENS_GATEWAY_CHAIN_ID)
//   REGISTER a v2 payment name (stealth meta + consumer pair)
//   RESOLVE  a driver that mimics the wallet's CCIP loop: call
//            resolver.resolve (ENSIP-10), catch the OffchainLookup revert
//            (ERC-3668), fetch the gateway URL template, and submit the
//            signed answer through resolver.resolveWithProof on-chain
//   ASSERT   (a) two resolutions of the same name answer two DIFFERENT
//            destinations; (b) announce-before-return — the announcement row
//            exists by the time the gateway's HTTP response lands, BEFORE the
//            wallet's callback; (c) a tampered result and an expired
//            signature both revert in resolveWithProof; (d) coinType routing
//            (ENSIP-11): the served funds chain answers and mints a row, an
//            unserved coinType 404s and mints NOTHING; (e) paying the
//            resolved destinations and running the sweeper library lands the
//            funds in the pool for the REGISTERED keys (self-scan discovery);
//            (f) the public feed carries no attribution, and no payment or
//            sweep tx leaks the label or any registered key.
//
// The leg deploys NO ENS registry: the driver enters at the ENSIP-10
// resolver directly (resolve -> OffchainLookup -> gateway -> resolveWithProof),
// which is the loop a wallet runs AFTER its registry walk found the resolver.
// The registry walk itself (and real MetaMask behavior) is exercised by the
// Sepolia environment, where the name's resolver is set on the live ENS
// registry (deploy/README.md runbook).
//
// POLL_MS=0 (tail off) + restart is the portal leg's determinism recipe: all
// chain-derived state lands exactly at boot ingest, so every flip assertion
// is a statement, not a race.

import { spawn, type ChildProcess } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  decodeAbiParameters,
  encodeAbiParameters,
  http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

import { packPubkey } from "@bongtu/core/pubkey";
import { coinTypeForChain, dnsEncodeName, gatewaySignatureHash, namehash, signGatewayResponse } from "@bongtu/core/ens";
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

import { GATE_B, RPC, deploy, deployStack, ok, step } from "../live/lib/e2e_harness.js";
import { anvilChain, makeRig } from "../live/lib/viem_client.js";
import type { Contract, Rig } from "../live/lib/viem_client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // deploy/gates -> repo root

// The recipient: a consumer wallet identity plus a stealth meta pair —
// seeds/scalars disjoint from every other driver (the priv leg uses c3/4242…).
const RECIPIENT = deriveIdentityFromSignature("0x" + "c4".repeat(65));
const STEALTH_VIEW_SCALAR = 626262626262626262626n;
const STEALTH_SPEND_SCALAR = 737373737373737373737n;
const NAME_LABEL = "name-payee";
// The ENS name a sender would type; the gateway serves its FIRST label.
const ENS_NAME = `${NAME_LABEL}.demo.eth`;
const OPERATOR_TOKEN = "gate-name-operator-token";

// The gateway's response-signing key — leg-owned, handed to the indexer via
// env and to the resolver as the derived signer ADDRESS. Disjoint from every
// actor key in the harness.
const GATEWAY_KEY_HEX = "7e".repeat(32);
const GATEWAY_KEY = hexToBytes(GATEWAY_KEY_HEX);

// Two payments from two distinct funded EOAs (anvil's well-known keys #6/#7 —
// the priv leg uses #8/#9; never the orchestrator key).
const PAYER_KEYS = [
  "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
  "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
];
const PAY_A = 757n;
const PAY_C = 919n;

/** Selectors the driver builds: ENSIP-1 addr(bytes32), ENSIP-11
 *  addr(bytes32,uint256). The resolver echoes msg.data, so the driver never
 *  hand-builds the outer resolve() calldata. */
const ADDR_SELECTOR = "0x3b3b57de";
const ADDR_COINTYPE_SELECTOR = "0xf1cb7e06";
/** ENSIP-10 IExtendedResolver interface id (what wallets probe via ERC-165). */
const EXTENDED_RESOLVER_INTERFACE_ID = "0x9061b923";

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

interface OffchainLookupArgs {
  sender: string;
  urls: string[];
  callData: `0x${string}`;
  callbackFunction: string;
  extraData: `0x${string}`;
}

/** Decode the OffchainLookup revert out of a viem read error (the wallet's
 *  ERC-3668 catch). Returns null when the error is anything else. */
function decodeOffchainLookup(e: unknown): OffchainLookupArgs | null {
  const revert = e instanceof BaseError ? e.walk((err) => err instanceof ContractFunctionRevertedError) : null;
  if (!(revert instanceof ContractFunctionRevertedError)) return null;
  if (revert.data?.errorName !== "OffchainLookup") return null;
  const [sender, urls, callData, callbackFunction, extraData] = revert.data.args as [
    string, readonly string[], `0x${string}`, string, `0x${string}`,
  ];
  return { sender, urls: [...urls], callData, callbackFunction, extraData };
}

/** The custom-error name a reverting read carries (for the negative cases). */
function revertErrorName(e: unknown): string | null {
  const revert = e instanceof BaseError ? e.walk((err) => err instanceof ContractFunctionRevertedError) : null;
  return revert instanceof ContractFunctionRevertedError ? revert.data?.errorName ?? null : null;
}

interface Resolved {
  destination: string;
  result: `0x${string}`;
  expires: bigint;
  sig: `0x${string}`;
  extraData: `0x${string}`;
  responseData: `0x${string}`;
}

export async function runNameLeg(rig: Rig): Promise<void> {
  step("NAME: leg-owned stack + priv factory + CCIP resolver + gateway indexer");
  const databaseUrl = process.env.E2E_NAME_DATABASE_URL || "";
  ok(databaseUrl !== "", "E2E_NAME_DATABASE_URL is set (name leg is mandatory — no silent skip)");

  const { token, pool } = await deployStack(rig, {
    batchSize: GATE_B,
    authorityPublicKey: [101n, 202n], // enterprise epoch key — unused by consumer ops
    mintAmount: 1_000_000n,
  });
  const dpv = await deploy(rig, "DepositPrivVerifier", "DepositPrivVerifier");
  const depMod = await deploy(rig, "DepositPrivModule", "DepositPrivModule", [pool.address, dpv.address]);
  await pool.write("registerModule", [depMod.address]);
  ok((await pool.read("registeredModules", [depMod.address])) === true, "DepositPrivModule registered");
  const factory = await deploy(rig, "PortalPrivFactory", "PortalPrivFactory", [rig.address]);
  const initCodeHash = String(await factory.read("sweeperInitCodeHash"));

  const port = Number(process.env.E2E_NAME_INDEXER_PORT || 8634);
  const indexerUrl = `http://127.0.0.1:${port}`;
  const gatewayUrlTemplate = `${indexerUrl}/ens/{sender}/{data}.json`;
  const gatewaySigner = privateKeyToAccount(("0x" + GATEWAY_KEY_HEX) as `0x${string}`).address;
  const resolver = await deploy(rig, "PortalPrivResolver", "PortalPrivResolver", [
    rig.address, gatewaySigner, [gatewayUrlTemplate],
  ]);
  ok((await resolver.read("supportsInterface", [EXTENDED_RESOLVER_INTERFACE_ID])) === true,
    "resolver advertises ENSIP-10 (IExtendedResolver) via ERC-165");
  console.log(`   pool=${pool.address} portalPrivFactory=${factory.address} resolver=${resolver.address}`);

  const indexerEnv = {
    RPC,
    POOL: String(pool.address),
    START_BLOCK: "0",
    DATABASE_URL: databaseUrl,
    PORTAL_PRIV_FACTORY: String(factory.address),
    PORTAL_OPERATOR_TOKEN: OPERATOR_TOKEN,
    ENS_RESOLVER: String(resolver.address),
    ENS_GATEWAY_KEY: GATEWAY_KEY_HEX,
    ENS_GATEWAY_CHAIN_ID: "31337", // the gate chain IS the funds chain
    PORT: String(port),
    POLL_MS: "0", // tail OFF — chain state lands at boot ingest (see header)
  };
  const child = { proc: spawnIndexer(indexerEnv) };
  try {
    await waitHealthy(indexerUrl);
    ok(true, `gateway indexer (ENS_RESOLVER + priv factory) healthy on :${port}`);

    // ================== REGISTER (v2: meta + consumer pair) =================
    step("NAME: register the v2 payment name (stealth meta + consumer pair)");
    const recipientCompressed = packPubkey(RECIPIENT.keypair.publicKey);
    const stealth = stealthKeysFromScalars(STEALTH_VIEW_SCALAR, STEALTH_SPEND_SCALAR);
    const pair = selfConsumerRecipient(RECIPIENT);
    await registerName(
      indexerUrl,
      buildNameRegistrationV2(
        NAME_LABEL,
        recipientCompressed,
        RECIPIENT.keypair.formattedPrivateKey,
        stealth.meta,
        { noteViewPub: pair.noteViewPub, kemEk: pair.kemEk },
      ),
    );

    // ==================== The wallet-shaped CCIP loop =======================
    // resolve (ENSIP-10) -> OffchainLookup -> gateway fetch -> resolveWithProof,
    // hand-rolled so the leg can assert BETWEEN the steps. viem's own ERC-3668
    // handling would run the whole loop inside readContract (exercised
    // separately below), so this driver reads through a ccipRead-disabled
    // client to catch the raw revert.
    const rawReader = createPublicClient({ transport: http(RPC), ccipRead: false });
    const nameWire = ("0x" + bytesToHex(dnsEncodeName(ENS_NAME))) as `0x${string}`;
    const node = namehash(ENS_NAME) as `0x${string}`;
    const resolveRaw = (inner: `0x${string}`): Promise<OffchainLookupArgs | null> =>
      rawReader.readContract({
        address: resolver.address,
        abi: resolver.abi,
        functionName: "resolve",
        args: [nameWire, inner],
      }).then(
        () => null,
        (e: unknown) => decodeOffchainLookup(e),
      );
    const ccipResolve = async (inner: `0x${string}`, legacyAddr: boolean): Promise<Resolved> => {
      const lookup = await resolveRaw(inner);
      ok(lookup !== null, "resolve reverted OffchainLookup (ERC-3668) — never answers from chain state");
      if (!lookup) throw new Error("no OffchainLookup to follow");
      ok(lookup.sender.toLowerCase() === String(resolver.address).toLowerCase()
        && lookup.urls[0] === gatewayUrlTemplate,
        "OffchainLookup carries the resolver as sender and the configured gateway URL");
      const url = lookup.urls[0]
        .replace("{sender}", lookup.sender.toLowerCase())
        .replace("{data}", lookup.callData);
      const httpResponse = await fetch(url);
      ok(httpResponse.ok, `gateway answered ${httpResponse.status}`);
      ok(httpResponse.headers.get("cache-control") === "no-store", "gateway response is Cache-Control: no-store");
      const { data: responseData } = (await httpResponse.json()) as { data: `0x${string}` };
      const [result, expires, sig] = decodeAbiParameters(
        [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
        responseData,
      ) as readonly [`0x${string}`, bigint, `0x${string}`];
      const destination = ((): string => {
        if (legacyAddr) {
          const [a] = decodeAbiParameters([{ type: "address" }], result);
          return (a as string).toLowerCase();
        }
        const [b] = decodeAbiParameters([{ type: "bytes" }], result);
        return (b as string).toLowerCase();
      })();
      // (b) announce-before-return: the row is on the public feed ALREADY —
      // the response is in hand and the wallet callback has not run yet.
      const rows = await getPortalAnnouncements(indexerUrl);
      ok(rows.some((r) => r.destination.toLowerCase() === destination),
        "announce-before-return: the announcement row exists when the HTTP response lands");
      // The wallet's final step: the on-chain callback verifies the signature.
      const answered = String(await resolver.read("resolveWithProof", [responseData, lookup.extraData])) as `0x${string}`;
      ok(answered.toLowerCase() === result.toLowerCase(), "resolveWithProof returns the gateway's result");
      return { destination, result, expires, sig, extraData: lookup.extraData, responseData };
    };

    // =============== RESOLVE x2 (legacy addr) + freshness ===================
    step("NAME: two CCIP resolutions of the same name (legacy addr(bytes32) form)");
    const legacyInner = (ADDR_SELECTOR + node.slice(2)) as `0x${string}`;
    const resolvedA = await ccipResolve(legacyInner, true);
    const resolvedB = await ccipResolve(legacyInner, true);
    ok(resolvedA.destination !== resolvedB.destination,
      "R2(a): two resolutions of the SAME name answered two DIFFERENT destinations");

    // The same lookup through viem's OWN ERC-3668 loop (rig.publicClient has
    // ccipRead on): a production client library drives fetch + callback
    // end-to-end against the real gateway, guarding the hand-rolled loop
    // above against divergence from client behavior.
    const viemResult = String(await resolver.read("resolve", [nameWire, legacyInner])) as `0x${string}`;
    const [viemAnswered] = decodeAbiParameters([{ type: "address" }], viemResult);
    const viemDestination = (viemAnswered as string).toLowerCase();
    ok(![resolvedA.destination, resolvedB.destination].includes(viemDestination),
      "viem's built-in CCIP loop resolved a THIRD fresh destination end-to-end");

    // Every minted row survives the wallet-side audit: the factory's addressOf
    // over the row's salt IS the answered destination, and the recipient's
    // view key re-derives the announced stealth address from R alone.
    const feed = await getPortalAnnouncements(indexerUrl);
    for (const resolved of [resolvedA, resolvedB]) {
      const row = feed.find((r) => r.destination.toLowerCase() === resolved.destination);
      ok(row !== undefined, "resolution has its announcement row on the public feed");
      if (!row) continue;
      const onChain = String(await factory.read("addressOf", [portalSalt(row.stealthAddr)]));
      ok(onChain.toLowerCase() === resolved.destination,
        "answered destination == portalPrivFactory.addressOf(portalSalt(stealthAddr)) on-chain");
      const rescan = scanStealthAnnouncement(STEALTH_VIEW_SCALAR, stealth.meta.spendPub, row.ephemeralPub);
      ok(rescan.address.toLowerCase() === row.stealthAddr.toLowerCase(),
        "recipient view key re-derives the announced stealth address from R alone");
    }

    // ================= (c) tamper + expiry revert in the callback ===========
    step("NAME: tampered result and expired signature revert in resolveWithProof");
    const tamperedResult = encodeAbiParameters([{ type: "address" }], [rig.address]);
    const tamperedResponse = encodeAbiParameters(
      [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
      [tamperedResult, resolvedA.expires, resolvedA.sig],
    );
    await resolver.read("resolveWithProof", [tamperedResponse, resolvedA.extraData]).then(
      () => ok(false, "tampered result must revert"),
      (e: unknown) => ok(revertErrorName(e) === "UntrustedSigner",
        "tampered result reverts UntrustedSigner (signature no longer covers it)"),
    );
    const pastExpiry = 1n; // far below any live block.timestamp
    const expiredDigest = gatewaySignatureHash(
      String(resolver.address), pastExpiry,
      hexToBytes(resolvedA.extraData.slice(2)), hexToBytes(resolvedA.result.slice(2)),
    );
    const expiredResponse = encodeAbiParameters(
      [{ type: "bytes" }, { type: "uint64" }, { type: "bytes" }],
      [resolvedA.result, pastExpiry, ("0x" + bytesToHex(signGatewayResponse(GATEWAY_KEY, expiredDigest))) as `0x${string}`],
    );
    await resolver.read("resolveWithProof", [expiredResponse, resolvedA.extraData]).then(
      () => ok(false, "expired signature must revert"),
      (e: unknown) => ok(revertErrorName(e) === "SignatureExpired",
        "a genuinely signed but expired response reverts SignatureExpired"),
    );

    // ================ (d) coinType routing (ENSIP-11, R13) ==================
    step("NAME: coinType routing — served chain answers, unserved coinType mints nothing");
    const servedInner = (ADDR_COINTYPE_SELECTOR + encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }], [node, coinTypeForChain(31337)],
    ).slice(2)) as `0x${string}`;
    const resolvedC = await ccipResolve(servedInner, false);
    ok(![resolvedA.destination, resolvedB.destination].includes(resolvedC.destination),
      "the coinType resolution derived its own fresh destination");

    const rowsBefore = (await getPortalAnnouncements(indexerUrl)).length;
    const foreignInner = (ADDR_COINTYPE_SELECTOR + encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }], [node, coinTypeForChain(8453)],
    ).slice(2)) as `0x${string}`;
    const foreignLookup = await resolveRaw(foreignInner);
    ok(foreignLookup !== null, "the stateless resolver still points an unserved coinType at the gateway");
    if (foreignLookup) {
      const url = foreignLookup.urls[0]
        .replace("{sender}", foreignLookup.sender.toLowerCase())
        .replace("{data}", foreignLookup.callData);
      const foreignResponse = await fetch(url);
      ok(foreignResponse.status === 404, "R13: the gateway answers an unserved coinType 404");
      ok((await getPortalAnnouncements(indexerUrl)).length === rowsBefore,
        "R13: the unserved coinType minted NO announcement row");
    }

    // ============== (e) PAY x2 + SWEEP (the R6 loop, headless) ==============
    step(`NAME: plain transfers ${PAY_A} + ${PAY_C} to two resolved destinations, then sweep`);
    const payments = [
      { destination: resolvedA.destination, amount: PAY_A },
      { destination: resolvedC.destination, amount: PAY_C },
    ];
    const paymentTxs: `0x${string}`[] = [];
    for (const [i, p] of payments.entries()) {
      const payer = makeRig({ chain: anvilChain(RPC), rpc: RPC, privateKey: PAYER_KEYS[i] });
      await token.write("transfer", [payer.address, p.amount]); // fund the payer
      const payerToken: Contract = payer.at(String(token.address), token.abi);
      const receipt = await payerToken.write("transfer", [p.destination, p.amount]);
      paymentTxs.push(receipt.transactionHash);
    }

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
    ok(poolAfter - poolBefore === PAY_A + PAY_C,
      `both sweeps grew the pool by exactly the payments (${PAY_A} + ${PAY_C})`);
    for (const p of payments) {
      ok(BigInt(await token.read("balanceOf", [p.destination])) === 0n,
        "resolved destination emptied by the sweep");
    }

    // ================== (f) the NEGATIVE GREP ===============================
    step("NAME: negative grep — no recipient identity in payment/sweep txs or the public feed");
    const sweepTxs = await (async (): Promise<`0x${string}`[]> => {
      const swept = (await getPortalAnnouncements(indexerUrl)).filter((r) => r.sweptTxHash !== null);
      // POLL_MS=0: the freshly minted swept rows only flip after restart —
      // recover the tx hashes from the chain instead (Swept events).
      const logs = await rig.publicClient.getLogs({ address: factory.address, fromBlock: 0n });
      return [...new Set([...swept.map((r) => r.sweptTxHash as `0x${string}`), ...logs.map((l) => l.transactionHash)])];
    })();
    const needles: [string, string][] = [
      ["label", NAME_LABEL],
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
      "public projection has no attribution field at all");

    // ========= FLIP + DISCOVERY (restart -> boot ingest, R6's landing) ======
    step("NAME: restart indexer -> paid rows flip swept; recipient self-scan finds both payments");
    await stopIndexer(child.proc);
    child.proc = spawnIndexer(indexerEnv);
    await waitHealthy(indexerUrl);

    const records = await getPortalAnnouncements(indexerUrl);
    for (const p of payments) {
      const rec = records.find((r) => r.destination.toLowerCase() === p.destination);
      ok(rec !== undefined && rec.swept === true && rec.sweptAmount === p.amount.toString(),
        `record flipped swept with the proof-bound amount (${p.amount})`);
    }
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
    ok(unspentValues.includes(PAY_A.toString()) && unspentValues.includes(PAY_C.toString()),
      `R6: self-scan discovered BOTH resolved payments as unspent notes (${PAY_A}, ${PAY_C})`);
  } finally {
    await stopIndexer(child.proc);
  }
}
