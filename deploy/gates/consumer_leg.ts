// The issue-#6 CONSUMER leg of the M0 DoD gate (e2e_orchestrator.ts calls it
// after the portal leg) — the consumer (no-auditor) family end to end with NO
// arbiter anywhere in the loop:
//
//   DEPLOY    a fresh enterprise B=16 stack (deployStack — real verifiers,
//             version-1 proxy), then the OPMOD §7 migration: consumer
//             verifiers + 5 modules + ONE upgradeToAndCall carrying
//             reinitializeV3(modules) — the profile-deploy path the campaign
//             ships (test_upgrade_v3.sh drills the forge-script twin at B=256)
//   INDEXER   the real apps/indexer service in PUBLIC mode (no AUTHORITY_KEY,
//             no AUTHORITY_KEM_KEY) against its own Postgres database
//             (E2E_CONSUMER_DATABASE_URL — e2e_m0.sh provisions it)
//   OPS       REAL CPU-proved consumer ops through the modules:
//             depositPriv mint (third-party recipient!), transferPriv spend,
//             withdrawPriv exit (proof-bound recipient), and a disbursePriv
//             1x16 batch WITH its OPMOD §5 chunk txs (chunkArity 6 => K=3,
//             submitted out of order)
//   REPLAY    disbursePriv256: the committed GPU fixture calldata replayed
//             against a second B=256 pool + real DisbursePriv256Verifier on
//             the same anvil (batch tx + all 3 chunk txs; GPU not required)
//   SELF-SCAN the recipient discovers its balance via packages/client
//             selfscan primitives from the PUBLIC feed with only its own keys
//             (viewTag filter -> Decaps -> hybrid decrypt -> leaf-match),
//             then SPENDS a batch-INTERIOR note whose membership path comes
//             from the AUTH-FREE GET /path (the §4.4 public batch fill) — the
//             arbiter-free assertion path end to end.
//
// No silent skip: a missing E2E_CONSUMER_DATABASE_URL is a loud ok() failure,
// exactly the portal leg's posture.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { encodeFunctionData, keccak256, type Abi, type Hex } from "viem";

import { ImtTree, foldToRoot } from "@bongtu/core/imt";
import { commitment, nullifier } from "@bongtu/core/note";
import { sealConsumerOutput, consumerDisclosureElements } from "@bongtu/core/consumer";
import type { SealedConsumerOutput } from "@bongtu/core/consumer";
import { getHead, getNullifiers, getPath, IndexerClient } from "@bongtu/core/indexerApi";
import type { PointInput } from "@bongtu/core/babyjub";
import { deriveIdentityFromSignature } from "@bongtu/client/derive";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import { buildConsumerTransferRequest, selfConsumerRecipient } from "@bongtu/client/consumer";
import { submitTransferPriv } from "@bongtu/client/consumer";
import type { Connection } from "@bongtu/client/connection";
import type { Calldata } from "@bongtu/core/proving";
import { runSelfScan, EMPTY_SCAN_STATE } from "@bongtu/client/selfscan";
import type { SelfScanState } from "@bongtu/client/selfscan";

import {
  H, GATE_B, RPC, deploy, deployStack, deployPoolProxy, artifact,
  prove as harnessProve, ok, step,
} from "../live/lib/e2e_harness.js";
import { proofArgs } from "../live/lib/viem_client.js";
import type { Contract, Rig } from "../live/lib/viem_client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", ".."); // deploy/gates -> repo root

const prove = (name: string, input: unknown) => harnessProve(name, input, { verbose: true });

// ---------------------------------------------------------------------------
// deterministic actors + per-tx crypto (labels/scalars disjoint from every
// other driver in the repo)
// ---------------------------------------------------------------------------

// Wallet identities exactly as the real wallet derives them: one 65-byte
// signature seed -> (spend keypair, note-layer view keypair, ML-KEM keypair).
const mkIdentity = (byte: string): ConsumerWalletIdentity =>
  deriveIdentityFromSignature("0x" + byte.repeat(65));
const SENDER = mkIdentity("a1");
const RECIPIENT = mkIdentity("b2");
// throwaway batch recipients (distinct per slot, OPMOD §4.5)
const THROWAWAY = Array.from({ length: 16 }, (_, i) =>
  mkIdentity((0x30 + i).toString(16).padStart(2, "0")),
);

// fresh ephemeral ECDH key + nonce PER TRANSACTION (never reuse a (key, nonce)
// pair across txs)
const ECDH_DEP1 = 910000000000000000001n;
const ECDH_TRF1 = 920000000000000000003n;
const ECDH_WDR1 = 930000000000000000007n;
const ECDH_DEP2 = 940000000000000000009n;
const ECDH_DISB = 950000000000000000011n;
const ECDH_SPEND = 960000000000000000013n;
const NONCE_DEP1 = 777000000001n;
const NONCE_TRF1 = 777000000002n;
const NONCE_WDR1 = 777000000003n;
const NONCE_DEP2 = 777000000004n;
const NONCE_DISB = 777000000005n;
const NONCE_SPEND = 777000000006n;

// salts (distinct per note; family disjoint from harness 5e6-7e6)
const sal = (i: number): bigint => 8800000n + BigInt(i);

const CHUNK_ARITY = 6; // => K = 3 (6 + 6 + 4) at B=16 — multi-chunk transport

const sha = (label: string): Uint8Array => new Uint8Array(createHash("sha256").update(label).digest());
const kemHex = (b: Uint8Array): string => "0x" + Buffer.from(b).toString("hex");
const concatHex = (parts: string[]): string => "0x" + parts.map((p) => p.replace(/^0x/, "")).join("");
const ZERO32 = ("0x" + "00".repeat(32)) as Hex;

/** Seal one output note to an identity (deterministic encapsulation). */
function sealTo(
  id: ConsumerWalletIdentity,
  value: bigint,
  salt: bigint,
  ephemeralPriv: bigint,
  encryptionNonce: bigint,
  index: number,
  label: string,
): SealedConsumerOutput {
  return sealConsumerOutput({
    value,
    salt,
    ephemeralPriv,
    viewPub: id.viewKeypair.publicKey,
    kemEk: id.kemKeypair.ek,
    encryptionNonce,
    index,
    encapSeed: sha(`bongtu/consumer-leg/encap/${label}/${index}`),
  });
}

interface PlannedOutput {
  id: ConsumerWalletIdentity;
  value: bigint;
  salt: bigint;
  seal: SealedConsumerOutput;
  commitment: bigint;
}

function planOutputs(
  plan: { id: ConsumerWalletIdentity; value: bigint; salt: bigint }[],
  ephemeralPriv: bigint,
  encryptionNonce: bigint,
  label: string,
): PlannedOutput[] {
  return plan.map((p, i) => ({
    ...p,
    seal: sealTo(p.id, p.value, p.salt, ephemeralPriv, encryptionNonce, i, label),
    commitment: commitment(p.value, p.salt, p.id.keypair.publicKey),
  }));
}

/** The output-side witness fields (identical field grammar across all five
 *  consumer circuits — circuits/fixtures/consumer_lib.ts outputSide). */
function outputSide(outs: PlannedOutput[]): {
  outputCommitments: bigint[];
  outputValues: bigint[];
  outputSalts: bigint[];
  outputOwnerPublicKeys: PointInput[];
  outputViewPublicKeys: PointInput[];
  kemSs: bigint[][];
} {
  return {
    outputCommitments: outs.map((o) => o.commitment),
    outputValues: outs.map((o) => o.value),
    outputSalts: outs.map((o) => o.salt),
    outputOwnerPublicKeys: outs.map((o) => o.id.keypair.publicKey),
    outputViewPublicKeys: outs.map((o) => o.id.viewKeypair.publicKey),
    kemSs: outs.map((o) => [o.seal.kemSs[0], o.seal.kemSs[1]]),
  };
}

// ---------------------------------------------------------------------------
// the public indexer (spawn/stop — the portal-leg pattern, minus every key)
// ---------------------------------------------------------------------------

function spawnIndexer(env: Record<string, string>): ChildProcess {
  const proc = spawn(process.execPath, ["--import", "tsx", "apps/indexer/src/index.ts"], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const relay = (data: unknown): void => {
    process.stdout.write(String(data).replace(/^(?=.)/gm, "   [pub-indexer] "));
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
    setTimeout(() => proc.kill("SIGKILL"), 8000).unref();
  });
}

async function waitFor(label: string, cond: () => Promise<boolean>, tries = 120): Promise<void> {
  for (const _ of Array(tries).keys()) {
    const done = await cond().catch(() => false);
    if (done) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`timed out waiting for: ${label}`);
}

// ---------------------------------------------------------------------------
// the leg
// ---------------------------------------------------------------------------

export async function runConsumerLeg(rig: Rig): Promise<void> {
  step("CONSUMER (issue #6): profile deploy — enterprise B=16 stack + V3 module upgrade");
  const databaseUrl = process.env.E2E_CONSUMER_DATABASE_URL || "";
  ok(databaseUrl !== "", "E2E_CONSUMER_DATABASE_URL is set (consumer leg is mandatory — no silent skip)");

  // A second, leg-owned enterprise stack on the shared anvil (the spend-cycle
  // pool keeps its own history; this leg owns its feed end to end).
  const { poseidon, token, pool } = await deployStack(rig, {
    batchSize: GATE_B,
    authorityPublicKey: [101n, 202n], // enterprise epoch key — unused by consumer ops
    mintAmount: 1_000_000n,
  });
  console.log(`   pool=${pool.address} token=${token.address}`);

  // ---- the OPMOD §7 migration: verifiers + modules + ONE upgradeToAndCall --
  const dpv = await deploy(rig, "DepositPrivVerifier", "DepositPrivVerifier");
  const tpv = await deploy(rig, "TransferPrivVerifier", "TransferPrivVerifier");
  const t10x2pv = await deploy(rig, "Transfer10x2PrivVerifier", "Transfer10x2PrivVerifier");
  const wpv = await deploy(rig, "WithdrawPrivVerifier", "WithdrawPrivVerifier");
  const dspv = await deploy(rig, "DisbursePrivVerifier", "DisbursePrivVerifier"); // the 1x16 twin: pool B = 16
  const depMod = await deploy(rig, "DepositPrivModule", "DepositPrivModule", [pool.address, dpv.address]);
  const trfMod = await deploy(rig, "TransferPrivModule", "TransferPrivModule", [pool.address, tpv.address]);
  const t10Mod = await deploy(rig, "Transfer10x2PrivModule", "Transfer10x2PrivModule", [pool.address, t10x2pv.address]);
  const wdrMod = await deploy(rig, "WithdrawPrivModule", "WithdrawPrivModule", [pool.address, wpv.address]);
  const disMod = await deploy(rig, "ConsumerDisburseModule", "ConsumerDisburseModule", [
    pool.address, dspv.address, BigInt(CHUNK_ARITY),
  ]);
  const modules = [depMod, trfMod, t10Mod, wdrMod, disMod];

  const preRoot = (await pool.read("root")).toString();
  const newImpl = await deploy(rig, "BongtuPool", "BongtuPool");
  await pool.write("upgradeToAndCall", [
    newImpl.address,
    encodeFunctionData({
      abi: pool.abi as Abi,
      functionName: "reinitializeV3",
      args: [modules.map((m) => m.address)],
    }),
  ]);
  const allRegistered = await modules.reduce<Promise<boolean>>(
    async (accP, m) => (await accP) && (await pool.read("registeredModules", [m.address])) === true,
    Promise.resolve(true),
  );
  ok(allRegistered, "reinitializeV3 registered all 5 consumer modules");
  ok((await pool.read("root")).toString() === preRoot, "upgrade preserved the tree root");

  // ---- the PUBLIC indexer (no arbiter key anywhere) ------------------------
  const port = Number(process.env.E2E_CONSUMER_INDEXER_PORT || 8632);
  const url = `http://127.0.0.1:${port}`;
  const child = { proc: spawnIndexer({
    RPC,
    POOL: String(pool.address),
    START_BLOCK: "0",
    DATABASE_URL: databaseUrl,
    PORT: String(port),
    POLL_MS: "250", // live tail: the leg's tx -> scan cycles need fresh ingest
  }) };
  try {
    await waitHealthy(url);
    const notesStatus = (await fetch(`${url}/notes?owner=0x00`)).status;
    ok(notesStatus === 404, `public mode: /notes does not exist (got ${notesStatus})`);

    const oracle = new ImtTree(H, GATE_B);
    const matchRoot = async (label: string): Promise<void> => {
      ok((await pool.read("root")).toString() === oracle.getRoot().toString(),
        `${label}: contract.root == ImtTree oracle root`);
    };

    // ======================= depositPriv (mint) ===========================
    step("CONSUMER depositPriv: mint 700 -> RECIPIENT (third party!) + 1300 -> SENDER");
    const dep1 = planOutputs(
      [
        { id: RECIPIENT, value: 700n, salt: sal(1) },
        { id: SENDER, value: 1300n, salt: sal(2) },
      ],
      ECDH_DEP1, NONCE_DEP1, "dep1",
    );
    {
      const input = {
        ...outputSide(dep1),
        ecdhPrivateKey: ECDH_DEP1,
        encryptionNonce: NONCE_DEP1,
      };
      const { a, b, c, pub } = await prove("depositPriv", input);
      ok(BigInt(pub[0]) === 2000n, "depositPriv out (pub[0]) == 2000");
      ok(BigInt(pub[13]) === dep1[0].commitment && BigInt(pub[14]) === dep1[1].commitment,
        "depositPriv output commitments (pub[13..14]) == plan");
      const mod = rig.at(depMod.address, artifact("DepositPrivModule", "DepositPrivModule").abi as Abi);
      oracle.appendLeaf(dep1[0].commitment); // leaf 0 — RECIPIENT
      oracle.appendLeaf(dep1[1].commitment); // leaf 1 — SENDER
      const balBefore: bigint = await token.read("balanceOf", [pool.address]);
      await mod.write("depositPriv", [
        ...proofArgs({ a, b, c, pub }),
        dep1.map((o) => kemHex(o.seal.kemCiphertext)),
      ]);
      await matchRoot("after depositPriv");
      ok((await token.read("balanceOf", [pool.address])) - balBefore === 2000n,
        "depositPriv pulled `out` into the core escrow");
    }

    // ======================= transferPriv (spend) =========================
    // THIS op runs the @bongtu/client path end to end (issue #13 S7): witness
    // assembly by consumerBuild (buildConsumerTransferRequest) and the tx by
    // consumerSubmit (submitTransferPriv) over a real Connection on the leg's
    // anvil rig, against the REAL circuit + module. A wrong ABI fragment or
    // witness layout in the client therefore reverts on-chain right here in CI.
    // Every other op keeps the leg-local assembly on purpose: that path is the
    // independent reference the client builders are checked against.
    step("CONSUMER transferPriv via @bongtu/client: SENDER spends note(1300) -> 500 RECIPIENT + 800 change");
    const zerosPath: bigint[] = new Array(H).fill(0n);
    const connection: Connection = {
      address: rig.address,
      walletClient: rig.walletClient,
      publicClient: rig.publicClient,
      injected: null,
      transport: "injected",
    };
    const trf1 = await (async (): Promise<{ commitment: bigint }[]> => {
      const { siblings } = oracle.merklePath(1);
      const built = buildConsumerTransferRequest(
        SENDER,
        [{ value: "1300", salt: sal(2).toString(), leafIndex: 1 }],
        [{ root: oracle.getRoot().toString(), pathElements: siblings.map(String), leafIndex: 1 }],
        selfConsumerRecipient(RECIPIENT),
        "500",
        {
          ecdhPrivateKey: ECDH_TRF1.toString(),
          encryptionNonce: NONCE_TRF1.toString(),
          payeeSalt: sal(3).toString(),
          changeSalt: sal(4).toString(),
          padSalts: [sal(5).toString()],
          // the same deterministic seeds sealTo draws for this label, so the
          // sealed bytes stay reproducible run to run
          encapSeeds: [sha("bongtu/consumer-leg/encap/trf1/0"), sha("bongtu/consumer-leg/encap/trf1/1")],
        },
      );
      ok(built.request.circuit === "transferPriv" && built.meta.membershipOk,
        "client builder assembled transferPriv with a membership that folds to the live root");
      ok(built.meta.changeValue === "800", "client builder conserves value: change == 800");
      const { a, b, c, pub } = await prove("transferPriv", built.request.input);
      const outs = built.meta.outputCommitments.map(BigInt);
      oracle.appendLeaf(outs[0]); // leaf 2 — RECIPIENT payment
      oracle.appendLeaf(outs[1]); // leaf 3 — SENDER change
      const res = await submitTransferPriv(
        connection,
        { a, b, c, pub } as Calldata,
        built.meta.kemCiphertexts,
        "https://anvil.invalid",
        trfMod.address,
      );
      ok(/^0x[0-9a-f]{64}$/i.test(res.txHash), "consumerSubmit resolved a tx hash after the receipt");
      await matchRoot("after transferPriv (client-built, client-submitted)");
      ok(await pool.read("nullifierUsed", [BigInt(built.meta.nullifiers[0])]),
        "transferPriv marked the spent nullifier");
      return outs.map((commitment) => ({ commitment }));
    })();

    // ======================= withdrawPriv (exit) ==========================
    step("CONSUMER withdrawPriv: SENDER exits 750 ERC-20 (proof-bound recipient) + 50 change");
    const wdr1 = planOutputs([{ id: SENDER, value: 50n, salt: sal(6) }], ECDH_WDR1, NONCE_WDR1, "wdr1");
    {
      const padSalt = sal(7);
      const { siblings } = oracle.merklePath(3);
      const input = {
        nullifiers: [nullifier(800n, sal(4), SENDER.keypair.formattedPrivateKey), 0n],
        inputCommitments: [trf1[1].commitment, commitment(0n, padSalt, SENDER.keypair.publicKey)],
        inputValues: [800n, 0n],
        inputSalts: [sal(4), padSalt],
        inputOwnerPrivateKey: SENDER.keypair.formattedPrivateKey,
        ecdhPrivateKey: ECDH_WDR1,
        root: oracle.getRoot(),
        pathElements: [siblings, zerosPath],
        leafIndices: [3n, 0n],
        enabled: [1n, 0n],
        ...outputSide(wdr1),
        encryptionNonce: NONCE_WDR1,
        recipient: BigInt(rig.address),
      };
      const { a, b, c, pub } = await prove("withdrawPriv", input);
      ok(BigInt(pub[0]) === 750n, "withdrawPriv out (pub[0]) == 750");
      const mod = rig.at(wdrMod.address, artifact("WithdrawPrivModule", "WithdrawPrivModule").abi as Abi);
      oracle.appendLeaf(wdr1[0].commitment); // leaf 4 — SENDER residual change
      const balBefore: bigint = await token.read("balanceOf", [rig.address]);
      await mod.write("withdrawPriv", [
        ...proofArgs({ a, b, c, pub }),
        wdr1.map((o) => kemHex(o.seal.kemCiphertext)),
        ZERO32,
        0,
      ]);
      await matchRoot("after withdrawPriv");
      ok((await token.read("balanceOf", [rig.address])) - balBefore === 750n,
        "withdrawPriv pushed 750 ERC-20 to the proof-bound recipient");
    }

    // ================== depositPriv #2 (batch funding) ====================
    step("CONSUMER depositPriv#2: mint the disburse funding note (1360 -> SENDER)");
    const dep2 = planOutputs(
      [
        { id: SENDER, value: 1360n, salt: sal(8) },
        { id: SENDER, value: 0n, salt: sal(9) },
      ],
      ECDH_DEP2, NONCE_DEP2, "dep2",
    );
    {
      const input = { ...outputSide(dep2), ecdhPrivateKey: ECDH_DEP2, encryptionNonce: NONCE_DEP2 };
      const { a, b, c, pub } = await prove("depositPriv", input);
      const mod = rig.at(depMod.address, artifact("DepositPrivModule", "DepositPrivModule").abi as Abi);
      oracle.appendLeaf(dep2[0].commitment); // leaf 5
      oracle.appendLeaf(dep2[1].commitment); // leaf 6
      await mod.write("depositPriv", [
        ...proofArgs({ a, b, c, pub }),
        dep2.map((o) => kemHex(o.seal.kemCiphertext)),
      ]);
      await matchRoot("after depositPriv#2");
    }

    // ============ disbursePriv 1x16 + OPMOD §5 chunk transport =============
    step("CONSUMER disbursePriv(16): batch mint (RECIPIENT at interior slot 3) + K=3 chunk txs");
    const RCPT_SLOT = 3;
    const RCPT_BATCH_VALUE = 260n;
    const batchPlan = Array.from({ length: GATE_B }, (_, i) => {
      if (i === RCPT_SLOT) return { id: RECIPIENT, value: RCPT_BATCH_VALUE, salt: sal(20 + i) };
      if (i < 12) return { id: THROWAWAY[i], value: 100n, salt: sal(20 + i) };
      return { id: THROWAWAY[i], value: 0n, salt: sal(20 + i) }; // §4.5 pads
    });
    const batch = planOutputs(batchPlan, ECDH_DISB, NONCE_DISB, "disb");
    const batchV = batch.reduce((a, o) => a + o.value, 0n);
    ok(batchV === 1360n, "batch values sum to the funding note");
    const batchId = GATE_B; // frontier 7 pads to 16; the subtree attaches there
    const chunks = [
      concatHex(batch.slice(0, 6).map((o) => kemHex(o.seal.kemCiphertext))),
      concatHex(batch.slice(6, 12).map((o) => kemHex(o.seal.kemCiphertext))),
      concatHex(batch.slice(12, 16).map((o) => kemHex(o.seal.kemCiphertext))),
    ];
    const chunkHashes = chunks.map((c) => keccak256(c as Hex));
    {
      const { siblings } = oracle.merklePath(5);
      const outSide = outputSide(batch);
      const input = {
        nullifiers: [nullifier(1360n, sal(8), SENDER.keypair.formattedPrivateKey)],
        inputCommitments: [dep2[0].commitment],
        inputValues: [1360n],
        inputSalts: [sal(8)],
        inputOwnerPrivateKey: SENDER.keypair.formattedPrivateKey,
        ecdhPrivateKey: ECDH_DISB,
        root: oracle.getRoot(),
        pathElements: [siblings],
        leafIndices: [5n],
        enabled: [1n],
        ...outSide,
        encryptionNonce: NONCE_DISB,
      };
      const { a, b, c, pub } = await prove("disbursePriv", input);
      const subtreeRoot = oracle.computeSubtreeRoot(outSide.outputCommitments);
      ok(BigInt(pub[3]) === subtreeRoot, "disbursePriv subtreeRoot (pub[3]) == oracle fold");
      const disclosure = consumerDisclosureElements(
        batch.map((o) => o.seal.cipherText),
        batch.map((o) => o.seal.viewTag),
        outSide.outputCommitments,
      );
      const mod = rig.at(disMod.address, artifact("ConsumerDisburseModule", "ConsumerDisburseModule").abi as Abi);
      oracle.attachSubtree(subtreeRoot, outSide.outputCommitments);
      await mod.write("disbursePriv256", [...proofArgs({ a, b, c, pub }), disclosure, chunkHashes]);
      await matchRoot("after disbursePriv attach");
      ok(await pool.read("nullifierUsed", [input.nullifiers[0]]), "disbursePriv marked the funding nullifier");

      // OPMOD §5: permissionless, order-free chunk completion (out of order on purpose)
      await mod.write("submitDisburseKemChunk", [BigInt(batchId), 2n, chunks[2]]);
      await mod.write("submitDisburseKemChunk", [BigInt(batchId), 0n, chunks[0]]);
      await mod.write("submitDisburseKemChunk", [BigInt(batchId), 1n, chunks[1]]);
      const allAccepted = await [0n, 1n, 2n].reduce<Promise<boolean>>(
        async (accP, i) => (await accP) && (await mod.read("kemChunkAccepted", [BigInt(batchId), i])) === true,
        Promise.resolve(true),
      );
      ok(allAccepted, "all K=3 kem chunks accepted on-chain");
    }

    // ============== disbursePriv256: committed fixture replay ==============
    step("CONSUMER disbursePriv256: replay the committed GPU fixture (B=256 pool, real verifier)");
    await runDisbursePriv256Replay(rig, poseidon.address, token.address);

    // ==================== SELF-SCAN (the campaign assertion) ===============
    step("SELF-SCAN: RECIPIENT discovers balance from the PUBLIC feed with only its own keys");
    const expectedLeaves = oracle.getNextLeafIndex(); // 32 after the batch
    await waitFor("public indexer ingests to the pool head", async () => {
      const head = await getHead(url);
      return head.nextLeafIndex === expectedLeaves;
    });

    const io = new IndexerClient(url); // satisfies SelfScanIo structurally
    const scanned = await (async (): Promise<SelfScanState> => {
      // kem chunk txs are fetched by the tail (eth_getTransactionByHash) — a
      // batch still assembling surfaces as PENDING, so re-scan until resolved.
      const first = await runSelfScan(io, RECIPIENT, EMPTY_SCAN_STATE);
      const settled = { state: first };
      await waitFor("self-scan resolves every pending batch + finds 3 notes", async () => {
        settled.state = await runSelfScan(io, RECIPIENT, settled.state);
        return settled.state.pending.length === 0 && settled.state.notes.length >= 3;
      }, 60);
      return settled.state;
    })();

    const unspent = scanned.notes.filter((n) => !n.spent);
    const balance = unspent.reduce((a, n) => a + BigInt(n.value), 0n);
    ok(balance === 700n + 500n + RCPT_BATCH_VALUE,
      `self-scan balance == 700 + 500 + ${RCPT_BATCH_VALUE} (deposit + transfer + batch-interior note)`);
    const batchNote = scanned.notes.find((n) => n.leafIndex === batchId + RCPT_SLOT);
    ok(batchNote !== undefined && BigInt(batchNote.value) === RCPT_BATCH_VALUE,
      `batch-INTERIOR note (leaf ${batchId + RCPT_SLOT}) discovered via viewTag -> Decaps -> leaf-match`);
    ok(scanned.notes.some((n) => n.leafIndex === 0 && n.value === "700"),
      "depositPriv third-party mint discovered (leaf 0, path-fold confirmed)");
    ok(scanned.notes.some((n) => n.leafIndex === 2 && n.value === "500"),
      "transferPriv payment discovered (leaf 2, path-fold confirmed)");

    // ========== SPEND a batch-interior note via the AUTH-FREE /path ========
    step("SPEND: RECIPIENT spends the batch-interior note with a membership path from auth-free GET /path");
    if (batchNote === undefined) throw new Error("unreachable: batchNote asserted above");
    const path = await getPath(url, batchNote.leafIndex); // NO auth material — §4.4 public batch fill
    ok(
      foldToRoot(BigInt(batchNote.commitment), path.siblings.map(BigInt), batchNote.leafIndex).toString()
        === path.root,
      "served siblings fold the recovered commitment to the served root (public batch interior)",
    );
    const spend = planOutputs(
      [
        { id: SENDER, value: 60n, salt: sal(40) },
        { id: RECIPIENT, value: 200n, salt: sal(41) },
      ],
      ECDH_SPEND, NONCE_SPEND, "spend",
    );
    {
      const padSalt = sal(42);
      const input = {
        nullifiers: [BigInt(batchNote.nullifier), 0n],
        inputCommitments: [BigInt(batchNote.commitment), commitment(0n, padSalt, RECIPIENT.keypair.publicKey)],
        inputValues: [BigInt(batchNote.value), 0n],
        inputSalts: [BigInt(batchNote.salt), padSalt],
        inputOwnerPrivateKey: RECIPIENT.keypair.formattedPrivateKey,
        ecdhPrivateKey: ECDH_SPEND,
        root: BigInt(path.root), // the indexer-served root — a known on-chain root
        pathElements: [path.siblings.map(BigInt), zerosPath],
        leafIndices: [BigInt(batchNote.leafIndex), 0n],
        enabled: [1n, 0n],
        ...outputSide(spend),
        encryptionNonce: NONCE_SPEND,
      };
      const { a, b, c, pub } = await prove("transferPriv", input);
      const mod = rig.at(trfMod.address, artifact("TransferPrivModule", "TransferPrivModule").abi as Abi);
      oracle.appendLeaf(spend[0].commitment); // leaf 32
      oracle.appendLeaf(spend[1].commitment); // leaf 33
      await mod.write("transferPriv", [
        ...proofArgs({ a, b, c, pub }),
        spend.map((o) => kemHex(o.seal.kemCiphertext)),
      ]);
      await matchRoot("after batch-interior spend");
      ok(await pool.read("nullifierUsed", [BigInt(batchNote.nullifier)]),
        "the batch-interior note's nullifier is spent on-chain");
    }

    // ==================== RE-SCAN (spent flip + change) ====================
    step("RE-SCAN: the spent batch note flips, the change note arrives — balance updates");
    await waitFor("indexer serves the spend's nullifier + leaves", async () => {
      const [head, nfs] = await Promise.all([getHead(url), getNullifiers(url)]);
      return head.nextLeafIndex === oracle.getNextLeafIndex() && nfs.includes(batchNote.nullifier);
    });
    const rescanned = await runSelfScan(io, RECIPIENT, scanned);
    const spentBatch = rescanned.notes.find((n) => n.leafIndex === batchNote.leafIndex);
    ok(spentBatch !== undefined && spentBatch.spent === true, "batch-interior note reads spent after re-scan");
    ok(rescanned.notes.some((n) => n.leafIndex === 33 && n.value === "200" && !n.spent),
      "spend change note (200) discovered unspent");
    const balance2 = rescanned.notes.filter((n) => !n.spent).reduce((a, n) => a + BigInt(n.value), 0n);
    ok(balance2 === 700n + 500n + 200n, "re-scanned balance == 700 + 500 + 200 (batch note spent into change)");

    console.log("\n   CONSUMER LEG COMPLETE — no arbiter key existed anywhere in this leg");
  } finally {
    await stopIndexer(child.proc);
  }
}

/** The committed disbursePriv256 GPU fixture, replayed as REAL calldata on a
 *  B=256 pool with the REAL DisbursePriv256Verifier (stub enterprise verifiers
 *  seed the fixture's membership leaf — the ConsumerModules.t.sol pattern).
 *  Chain-only by design: proving 3M constraints needs the GPU box; ACCEPTING
 *  the proof + the full chunk lifecycle needs only anvil. */
async function runDisbursePriv256Replay(rig: Rig, poseidonAddr: string, tokenAddr: string): Promise<void> {
  const fx = JSON.parse(
    readFileSync(join(ROOT, "chains", "evm", "test", "fixtures", "consumer_realproofs.json"), "utf8"),
  ).disbursePriv256 as {
    a: string[]; b: string[][]; c: string[]; pub: string[];
    seedLeaves: string[]; rootAfter: string; disclosure: string[];
    chunkArity: number; kemChunks: string[]; kemChunkHashes: string[];
  };
  const stub = (name: string) => deploy(rig, "StubVerifiers", name);
  const sdv = await stub("StubDepositVerifier");
  const swv = await stub("StubWithdrawVerifier");
  const sdsv = await stub("StubDisburseVerifier");
  const stv = await stub("StubTransferVerifier");
  const stv10 = await stub("StubTransfer10Verifier");
  const stv10x2 = await stub("StubTransfer10x2Verifier");
  const pool256 = await deployPoolProxy(rig, [
    poseidonAddr, sdv.address, swv.address, sdsv.address, stv.address, stv10.address, stv10x2.address,
    tokenAddr, 256n, [101n, 202n], ("0x" + "00".repeat(31) + "01") as Hex,
  ]);
  const v256 = await deploy(rig, "DisbursePriv256Verifier", "DisbursePriv256Verifier");
  const mod256 = await deploy(rig, "ConsumerDisburseModule", "ConsumerDisburseModule", [
    pool256.address, v256.address, BigInt(fx.chunkArity),
  ]);
  await pool256.write("registerModule", [mod256.address]);

  // seed the fixture's ONE membership leaf via a stub enterprise withdraw
  // (its change output is the only append — the single-leaf seeding pattern)
  const w: bigint[] = new Array(27).fill(0n);
  w[19] = BigInt(await pool256.read("root"));
  w[22] = BigInt(fx.seedLeaves[0]);
  w[26] = BigInt(rig.address);
  const dummy = { a: ["1", "2"], b: [["3", "4"], ["5", "6"]], c: ["7", "8"], pub: [] as string[] };
  await pool256.write("withdraw", [dummy.a, dummy.b, dummy.c, w, "0x" + "00".repeat(1088), ZERO32, 0]);
  ok(BigInt(await pool256.read("root")).toString() === BigInt(fx.pub[5]).toString(),
    "seeded B=256 pool root == the fixture proof's membership root (pub[5])");

  const mc = rig.at(mod256.address, artifact("ConsumerDisburseModule", "ConsumerDisburseModule").abi as Abi);
  await mc.write("disbursePriv256", [
    fx.a.map(BigInt), fx.b.map((r) => r.map(BigInt)), fx.c.map(BigInt), fx.pub.map(BigInt),
    fx.disclosure.map(BigInt), fx.kemChunkHashes,
  ]);
  ok((await pool256.read("nextLeafIndex")).toString() === "512",
    "disbursePriv256 attach: nextLeafIndex == 512 (pad 1->256 + 256-leaf subtree)");
  ok(BigInt(await pool256.read("root")).toString() === BigInt(fx.rootAfter).toString(),
    "disbursePriv256 post-attach root == fixture oracle rootAfter");

  // the OPMOD §5 chunk txs, out of order (86 + 86 + 84 outputs, K = 3)
  await mc.write("submitDisburseKemChunk", [256n, 1n, fx.kemChunks[1]]);
  await mc.write("submitDisburseKemChunk", [256n, 2n, fx.kemChunks[2]]);
  await mc.write("submitDisburseKemChunk", [256n, 0n, fx.kemChunks[0]]);
  const accepted = await [0n, 1n, 2n].reduce<Promise<boolean>>(
    async (accP, i) => (await accP) && (await mc.read("kemChunkAccepted", [256n, i])) === true,
    Promise.resolve(true),
  );
  ok(accepted, "all 3 committed kem chunks accepted (keccak-bound, permissionless)");
}
