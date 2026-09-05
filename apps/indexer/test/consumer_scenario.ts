// Consumer op-module conformance scenario (OPMOD §4.4/§5 U5): a SECOND fresh
// pool on the same anvil, driven with the COMMITTED consumer fixtures
// (chains/evm/test/fixtures/consumer_realproofs.json — real Groth16 proofs
// against the real consumer verifiers), so the indexer's consumer leg ingests
// exactly what a live chain would emit:
//
//   1. deploy pool (B=16) with always-accept enterprise verifier stubs (the
//      seeding trick of chains/evm/test/ConsumerModules.t.sol: the disbursePriv
//      fixture's membership root covers its two seed leaves, and a stubbed
//      enterprise deposit mints them as genuine tree writes) + the REAL
//      DepositPrivVerifier / DisbursePrivVerifier;
//   2. register a throwaway StubModule and remove it — the live registry
//      lifecycle the mirror must replay (balanced add/remove stream);
//   3. register DepositPrivModule + ConsumerDisburseModule(chunkArity=6 =>
//      K=3 chunks of 6/6/4 kem cts — the multi-chunk transport at dev size);
//   4. seed the fixture's 2 leaves, drive the committed depositPriv (a
//      root-free mint — appends @2,@3), then the committed disbursePriv
//      (proved against the seed-only root, still known after the mint —
//      any-historical-root semantics; the batch attaches @16);
//   5. submit chunks 0 and 2 OUT OF ORDER, leaving chunk 1 pending — the test
//      ingests here (kem-pending), then calls `submitFinalChunk` and
//      re-ingests (complete + assembly == the fixture's kem cts).
//
// Proving cost: zero — the fixtures ARE the proofs. Runs against E2E_RPC.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak256, type Hex } from "viem";

import {
  connectAnvil, deploy, deployPoolProxy, artifact, AUTHORITY_KEM,
} from "../../../deploy/live/lib/e2e_harness.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", ".."); // apps/indexer/test -> repo root

const CONSUMER_B = 16;
const CHUNK_ARITY = 6; // => K = 3 (6 + 6 + 4) — multi-chunk at dev size

interface ConsumerFixture {
  a: string[];
  b: string[][];
  c: string[];
  pub: string[];
  kemCiphertexts?: string[];
  disclosure?: string[];
  seedLeaves?: string[];
}

export interface ConsumerScenarioResult {
  poolAddr: string;
  depositModule: string;
  disburseModule: string;
  stubModule: string; // registered then removed — the mirror's removed row
  batchId: number; // the disbursePriv attach start (16)
  depositLeaves: [number, number]; // the depositPriv outputs' leaf indices
  depositCommitments: [string, string]; // decimal
  depositViewTags: [string, string]; // decimal
  depositKemCts: [string, string]; // 0x-hex
  disclosure: string[]; // decimal, 6*B elements
  kemCts: string[]; // 0x-hex per-output cts, leaf order (B entries)
  chunkHashes: string[]; // 0x-hex keccak256, K entries
  headRoot: string; // decimal, after everything but the final chunk
  nextLeafIndex: number;
  /** submit the withheld chunk 1 — called BETWEEN the test's two ingests. */
  submitFinalChunk: () => Promise<void>;
}

const abc = (fx: ConsumerFixture): [bigint[], bigint[][], bigint[]] => [
  fx.a.map(BigInt),
  fx.b.map((r) => r.map(BigInt)),
  fx.c.map(BigInt),
];
const dec = (x: bigint): string => x.toString();
const concatHex = (parts: string[]): string => "0x" + parts.map((p) => p.replace(/^0x/, "")).join("");

export async function runConsumerScenario(): Promise<ConsumerScenarioResult> {
  const rig = connectAnvil();
  const fixtures = JSON.parse(
    readFileSync(join(ROOT, "chains", "evm", "test", "fixtures", "consumer_realproofs.json"), "utf8"),
  ) as Record<string, ConsumerFixture>;
  const depFx = fixtures.depositPriv;
  const disFx = fixtures.disbursePriv;

  // ---- deploy: poseidon + enterprise verifier stubs + real consumer stack ---
  const posHex = readFileSync(join(ROOT, "chains", "evm", "test", "fixtures", "poseidon2.hex"), "utf8").trim();
  const posAddr = await rig.deploy([], posHex);
  const stub = async (name: string) => deploy(rig, "StubVerifiers", name);
  const [dv, wv, dsv, tv, tv10, tv10x2] = [
    await stub("StubDepositVerifier"),
    await stub("StubWithdrawVerifier"),
    await stub("StubDisburseVerifier"),
    await stub("StubTransferVerifier"),
    await stub("StubTransfer10Verifier"),
    await stub("StubTransfer10x2Verifier"),
  ];
  const token = await deploy(rig, "MockERC20", "MockERC20");
  const pool = await deployPoolProxy(rig, [
    posAddr, dv.address, wv.address, dsv.address, tv.address, tv10.address, tv10x2.address,
    token.address, BigInt(CONSUMER_B),
    [101n, 202n], // arbiter bjj pubkey: unused by consumer ops, any nonzero pair
    keccak256(AUTHORITY_KEM.publicKey),
  ]);
  await token.write("mint", [rig.address, 10_000_000n]);
  await token.write("approve", [pool.address, (1n << 255n)]);

  const depVerifier = await deploy(rig, "DepositPrivVerifier", "DepositPrivVerifier");
  const disVerifier = await deploy(rig, "DisbursePrivVerifier", "DisbursePrivVerifier");
  const depMod = await deploy(rig, "DepositPrivModule", "DepositPrivModule", [pool.address, depVerifier.address]);
  const disMod = await deploy(rig, "ConsumerDisburseModule", "ConsumerDisburseModule", [
    pool.address, disVerifier.address, BigInt(CHUNK_ARITY),
  ]);

  // ---- registry lifecycle the mirror must replay ----------------------------
  const stubMod = await deploy(rig, "OpModuleMocks", "StubModule", [pool.address]);
  await pool.write("registerModule", [stubMod.address]);
  await pool.write("removeModule", [stubMod.address]);
  await pool.write("registerModule", [depMod.address]);
  await pool.write("registerModule", [disMod.address]);

  // ---- seed the disbursePriv membership tree (stubbed enterprise deposit) ---
  // pub[14]/pub[15] carry the two seed leaves; everything else zero (amount 0).
  const seed = disFx.seedLeaves!.map(BigInt);
  const seedPub = Array.from({ length: 19 }, (_, i) => (i === 14 ? seed[0] : i === 15 ? seed[1] : 0n));
  const dummyA = [1n, 2n];
  const dummyB = [[3n, 4n], [5n, 6n]];
  const dummyC = [7n, 8n];
  const zeroKemCt = ("0x" + "00".repeat(1088)) as string;
  await pool.write("deposit", [dummyA, dummyB, dummyC, seedPub, zeroKemCt]);

  // ---- the committed depositPriv (root-free mint, appends @2/@3) ------------
  const [da, db, dc] = abc(depFx);
  const depPub = depFx.pub.map(BigInt);
  const depMc = rig.at(depMod.address, artifact("DepositPrivModule", "DepositPrivModule").abi);
  await depMc.write("depositPriv", [da, db, dc, depPub, depFx.kemCiphertexts!]);

  // ---- the committed disbursePriv (attaches @16) + 2 of 3 kem chunks --------
  const [xa, xb, xc] = abc(disFx);
  const disPub = disFx.pub.map(BigInt);
  const disclosure = disFx.disclosure!.map(BigInt);
  const kemCts = disFx.kemCiphertexts!;
  const chunks = [
    concatHex(kemCts.slice(0, 6)),
    concatHex(kemCts.slice(6, 12)),
    concatHex(kemCts.slice(12, 16)),
  ];
  const chunkHashes = chunks.map((c) => keccak256(c as Hex));
  const disMc = rig.at(disMod.address, artifact("ConsumerDisburseModule", "ConsumerDisburseModule").abi);
  await disMc.write("disbursePriv256", [xa, xb, xc, disPub, disclosure, chunkHashes]);
  const batchId = CONSUMER_B; // frontier 4 pads to 16, subtree attaches there
  // out of order on purpose: completion is permissionless and order-free
  await disMc.write("submitDisburseKemChunk", [BigInt(batchId), 2n, chunks[2]]);
  await disMc.write("submitDisburseKemChunk", [BigInt(batchId), 0n, chunks[0]]);

  const headRoot = BigInt(await pool.read("root"));
  const nextLeafIndex = Number(await pool.read("nextLeafIndex"));

  return {
    poolAddr: pool.address,
    depositModule: String(depMod.address).toLowerCase(),
    disburseModule: String(disMod.address).toLowerCase(),
    stubModule: String(stubMod.address).toLowerCase(),
    batchId,
    depositLeaves: [2, 3],
    depositCommitments: [dec(depPub[13]), dec(depPub[14])],
    depositViewTags: [dec(depPub[11]), dec(depPub[12])],
    depositKemCts: [depFx.kemCiphertexts![0], depFx.kemCiphertexts![1]],
    disclosure: disclosure.map(dec),
    kemCts,
    chunkHashes,
    headRoot: dec(headRoot),
    nextLeafIndex,
    submitFinalChunk: async () => {
      await disMc.write("submitDisburseKemChunk", [BigInt(batchId), 1n, chunks[1]]);
    },
  };
}
