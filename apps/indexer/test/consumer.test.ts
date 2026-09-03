// Consumer op-family ingest unit test (OPMOD §3.6/§4.4/§5/§1.4) — ANVIL-FREE.
//
// Drives `Indexer.applyLogs` with synthetic ParsedLog sequences the way
// ingest.test.ts does, but for the MODULE-emitted consumer family, in PUBLIC
// mode throughout (no arbiter key anywhere — the whole point of the family):
//   - registry mirror lifecycle: register/remove, the balanced-stream asserts
//     (double-add / remove-of-unknown = ingest corruption), replay convergence,
//     and the removed-module WATCH rule (an address with a kem-incomplete
//     batch stays in the watch-set until every chunk is accepted);
//   - the five op kinds land on the feed with receiver ct slices, viewTags,
//     nonces, ecdh pubkeys and kem cts — then the FULL S3.6 pipeline runs off
//     the feed alone (viewTag filter → Decaps → hybrid key → decrypt →
//     commitment == the tree leaf);
//   - OpApplied is the per-insert audit anchor: a disagreeing OpApplied throws;
//   - the §4.4 public batch fill: a fold-checked consumer disburse fills the
//     batch so path() serves REAL interiors (isPublicBatch => auth-free), a
//     tampered element alarms "mismatch" and fills nothing, and a bad-fold
//     publish (dh matches, commitments don't fold to subtreeRoot) alarms
//     instead of 500ing;
//   - kem chunk assembly: keccak recheck, out-of-order accept, pending vs
//     withheld vs accepted-unassembled vs complete, assembled per-output cts
//     == what was chunked;
//   - the ADDRESS GATE: forged pool-family events from a watched module (and
//     consumer events from an unwatched address) are dropped without touching
//     tree/registry/feed, while pool-emitted logs still apply;
//   - degrade posture: module-emitted chunk inconsistencies (unknown batch,
//     out-of-range index, duplicate accept) warn + drop instead of wedging;
//     an unconsumed OpApplied warns (alarm-class) and never wedges.
//
//   node --import tsx test/consumer.test.ts     # (== npm run test:consumer)

import { keccak256, type Hex } from "viem";
import { deriveKeypair, commitment } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import { ml_kem768 } from "@bongtu/core/kem";
import {
  sealConsumerOutput,
  openConsumerOutput,
  consumerViewTag,
  consumerDisclosureElements,
} from "@bongtu/core/consumer";
import { disclosureChain } from "@bongtu/core/envelope";
import { ecdhSharedSecret } from "@bongtu/core/note";
import { ImtTree } from "@bongtu/core/imt";
import { MirrorTree } from "../src/tree.js";
import { Indexer, type ParsedLog } from "../src/ingest.js";
import { events as eventsRoute } from "../src/api/routes/events.js";

const failures = { count: 0 };
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures.count++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
function step(t: string): void {
  console.log(`\n=== ${t} ===`);
}

const H = 8;
const B = 4;

const DUMMY_RPC = "http://127.0.0.1:1"; // never contacted
const POOL_ADDR = "0x" + "12".repeat(20);
const MOD_DEP = "0x" + "d1".repeat(20);
const MOD_TRF = "0x" + "d2".repeat(20);
const MOD_WDR = "0x" + "d3".repeat(20);
const MOD_DIS = "0x" + "d4".repeat(20);

// Recipient identities: spend keypair (commitments) + note-layer view keypair
// + ML-KEM keypair — the OPMOD §3.1 triple, test-local.
const SPEND = deriveKeypair(424242424242424242424242n);
const VIEW = deriveKeypair(515151515151515151515151n);
const KEM = ml_kem768.keygen(new Uint8Array(64).fill(7));

const dec = (x: bigint): string => x.toString();
const kemHex = (bytes: Uint8Array): string => "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const fakeKemCt = (seed: number): string => "0x" + (seed % 256).toString(16).padStart(2, "0").repeat(1088);
const concatHex = (parts: string[]): string => "0x" + parts.map((p) => p.replace(/^0x/, "")).join("");

interface Sim {
  oracle: ImtTree;
  log: (name: string, txHash: string, args: Record<string, unknown>, address?: string) => ParsedLog;
  tx: () => void;
  appended: (txHash: string, leaf: bigint) => { log: ParsedLog; leafIndex: number; root: bigint };
  opApplied: (
    txHash: string,
    module: string,
    fx: { startLeafIndex: number; nullifierCount: number; leafCount: number; subtreeRoot: bigint; root: bigint },
  ) => ParsedLog;
}

function makeSim(): Sim {
  const oracle = new ImtTree(H, B);
  const pos = { blockNumber: 0, logIndex: 0 };
  const tx = (): void => {
    pos.blockNumber++;
    pos.logIndex = 0;
  };
  const log = (name: string, txHash: string, args: Record<string, unknown>, address: string = POOL_ADDR): ParsedLog => ({
    name,
    blockNumber: pos.blockNumber,
    logIndex: pos.logIndex++,
    txHash,
    address,
    blockTimestamp: 1_700_000_000 + pos.blockNumber,
    args,
  });
  const appended = (txHash: string, leaf: bigint): { log: ParsedLog; leafIndex: number; root: bigint } => {
    const leafIndex = oracle.getNextLeafIndex();
    oracle.appendLeaf(leaf);
    const root = oracle.getRoot();
    return { log: log("Appended", txHash, { leafIndex: BigInt(leafIndex), leaf, root }), leafIndex, root };
  };
  const opApplied = (
    txHash: string,
    module: string,
    fx: { startLeafIndex: number; nullifierCount: number; leafCount: number; subtreeRoot: bigint; root: bigint },
  ): ParsedLog =>
    log("OpApplied", txHash, {
      module,
      startLeafIndex: BigInt(fx.startLeafIndex),
      nullifierCount: BigInt(fx.nullifierCount),
      leafCount: BigInt(fx.leafCount),
      subtreeRoot: fx.subtreeRoot,
      root: fx.root,
    });
  return { oracle, log, tx, appended, opApplied };
}

function makeIndexer(): Indexer {
  const ix = new Indexer({ rpc: DUMMY_RPC, pool: POOL_ADDR, startBlock: 0, authorityKey: null });
  ix.batchSize = B;
  ix.tree = new MirrorTree(H, B);
  return ix;
}

const register = (sim: Sim, txHash: string, module: string): ParsedLog[] => {
  sim.tx();
  return [sim.log("ModuleRegistered", txHash, { module })];
};
const remove = (sim: Sim, txHash: string, module: string): ParsedLog[] => {
  sim.tx();
  return [sim.log("ModuleRemoved", txHash, { module })];
};

async function main(): Promise<void> {
  // ---- the S3.6 sealed material for the depositPriv leg ---------------------
  const EPH = 313131313131313131313131n; // the op's ephemeral bjj scalar
  const NONCE = 987654321n;
  const value0 = 77n, salt0 = 5001n;
  const sealed0 = sealConsumerOutput({
    value: value0, salt: salt0, ephemeralPriv: EPH, viewPub: VIEW.publicKey,
    kemEk: KEM.publicKey, encryptionNonce: NONCE, index: 0,
    encapSeed: new Uint8Array(32).fill(3),
  });
  const pad1 = sealConsumerOutput({
    value: 0n, salt: 5002n, ephemeralPriv: EPH, viewPub: deriveKeypair(616161n).publicKey,
    kemEk: ml_kem768.keygen(new Uint8Array(64).fill(9)).publicKey, encryptionNonce: NONCE, index: 1,
    encapSeed: new Uint8Array(32).fill(4),
  });
  const oc0 = commitment(value0, salt0, SPEND.publicKey);
  const oc1 = commitment(0n, 5002n, deriveKeypair(717171n).publicKey);
  const ephPub = deriveKeypair(EPH).publicKey;

  const sim = makeSim();
  const ix = makeIndexer();

  const depositPrivLogs = ((): ParsedLog[] => {
    sim.tx();
    const a0 = sim.appended("0xcdep", oc0);
    const a1 = sim.appended("0xcdep", oc1);
    return [
      a0.log,
      a1.log,
      sim.opApplied("0xcdep", MOD_DEP, { startLeafIndex: a0.leafIndex, nullifierCount: 0, leafCount: 2, subtreeRoot: 0n, root: a1.root }),
      sim.log("DepositedPriv", "0xcdep", {
        firstLeafIndex: BigInt(a0.leafIndex), oc0, oc1, amount: value0,
        ecdhPublicKey: [ephPub[0], ephPub[1]],
        ctReceiver0: sealed0.cipherText, ctReceiver1: pad1.cipherText,
        viewTags: [sealed0.viewTag, pad1.viewTag],
        encryptionNonce: NONCE, root: a1.root,
        kemCiphertexts: [kemHex(sealed0.kemCiphertext), kemHex(pad1.kemCiphertext)],
      }, MOD_DEP),
    ];
  })();

  // transferPriv spending one real + one padded input, outputs to fresh owners.
  const t0 = commitment(30n, 6001n, deriveKeypair(818181n).publicKey);
  const t1 = commitment(47n, 6002n, deriveKeypair(919191n).publicKey);
  const transferPrivLogs = ((): ParsedLog[] => {
    sim.tx();
    const a0 = sim.appended("0xctrf", t0);
    const a1 = sim.appended("0xctrf", t1);
    return [
      a0.log,
      a1.log,
      sim.opApplied("0xctrf", MOD_TRF, { startLeafIndex: a0.leafIndex, nullifierCount: 1, leafCount: 2, subtreeRoot: 0n, root: a1.root }),
      sim.log("TransferredPriv", "0xctrf", {
        nullifiers: [1001n, 0n], outputCommitments: [t0, t1],
        ecdhPublicKey: [11n, 22n],
        ctReceiver0: [1n, 2n, 3n, 4n], ctReceiver1: [5n, 6n, 7n, 8n],
        viewTags: [12n, 200n], encryptionNonce: 111n, root: a1.root,
        kemCiphertexts: [fakeKemCt(1), fakeKemCt(2)],
      }, MOD_TRF),
    ];
  })();

  // withdrawPriv: one change leaf + the module's WithdrawAnnouncement pair.
  const chg = commitment(9n, 7001n, SPEND.publicKey);
  const REAL_R = "0x" + "c9".repeat(32);
  const withdrawPrivLogs = ((): ParsedLog[] => {
    sim.tx();
    const a0 = sim.appended("0xcwdr", chg);
    return [
      a0.log,
      sim.opApplied("0xcwdr", MOD_WDR, { startLeafIndex: a0.leafIndex, nullifierCount: 2, leafCount: 1, subtreeRoot: 0n, root: a0.root }),
      sim.log("WithdrawnPriv", "0xcwdr", {
        nullifiers: [1002n, 1003n], amount: 21n, changeCommitment: chg,
        ecdhPublicKey: [33n, 44n], ctChange: [9n, 8n, 7n, 6n], viewTag: 42n,
        encryptionNonce: 222n, root: a0.root,
        kemCiphertexts: [fakeKemCt(3)],
      }, MOD_WDR),
      sim.log("WithdrawAnnouncement", "0xcwdr", {
        recipient: BigInt("0x" + "ab".repeat(20)), stealthEphemeralPub: REAL_R, stealthViewTag: 5,
      }, MOD_WDR),
    ];
  })();

  // Consumer disburse: B=4 real outputs, disclosure = cts ++ tags ++ commits,
  // kem cts chunked at arity 2 => K = 2 chunks.
  const dOwners = Array.from({ length: B }, (_, i) => deriveKeypair(2100000n + BigInt(i)));
  const dVals = [10n, 20n, 30n, 40n];
  const dSalts = [8001n, 8002n, 8003n, 8004n];
  const dCommits = dOwners.map((o: Keypair, i) => commitment(dVals[i], dSalts[i], o.publicKey));
  const dCts = Array.from({ length: B }, (_, i) => [100n + BigInt(i), 200n + BigInt(i), 300n + BigInt(i), 400n + BigInt(i)]);
  const dTags = [7n, 250n, 0n, 99n];
  const dDisclosure = consumerDisclosureElements(dCts, dTags, dCommits);
  const dh = disclosureChain(dDisclosure);
  const dKemCts = Array.from({ length: B }, (_, i) => fakeKemCt(16 + i));
  const chunk0 = concatHex([dKemCts[0], dKemCts[1]]);
  const chunk1 = concatHex([dKemCts[2], dKemCts[3]]);
  const chunkHashes = [keccak256(chunk0 as Hex), keccak256(chunk1 as Hex)];

  const disburse = ((): { logs: ParsedLog[]; start: number; subtreeRoot: bigint } => {
    sim.tx();
    const subtreeRoot = sim.oracle.computeSubtreeRoot(dCommits);
    const start = Math.ceil(sim.oracle.getNextLeafIndex() / B) * B;
    sim.oracle.attachSubtree(subtreeRoot, dCommits);
    const root = sim.oracle.getRoot();
    return {
      start,
      subtreeRoot,
      logs: [
        sim.log("SubtreeAppended", "0xcdis", { startLeafIndex: BigInt(start), subtreeRoot, root }),
        sim.opApplied("0xcdis", MOD_DIS, { startLeafIndex: start, nullifierCount: 1, leafCount: 0, subtreeRoot, root }),
        sim.log("DisbursedPriv", "0xcdis", {
          batchId: BigInt(start), nullifier: 1004n, subtreeRoot, disclosureHash: dh,
          ecdhPublicKey: [55n, 66n], encryptionNonce: 333n, root,
          kemChunkHashes: chunkHashes,
        }, MOD_DIS),
        sim.log("DisbursePrivDisclosure", "0xcdis", { startLeafIndex: BigInt(start), disclosure: dDisclosure }, MOD_DIS),
      ],
    };
  })();

  const allLogs: ParsedLog[] = [
    ...register(sim, "0xreg1", MOD_DEP),
    ...register(sim, "0xreg2", MOD_TRF),
    ...register(sim, "0xreg3", MOD_WDR),
    ...register(sim, "0xreg4", MOD_DIS),
    ...depositPrivLogs,
    ...transferPrivLogs,
    ...withdrawPrivLogs,
    ...disburse.logs,
  ];

  step("APPLY: registry + all four consumer op kinds (PUBLIC mode, no arbiter key)");
  ix.applyLogs(allLogs);
  ok(ix.tree.root() === sim.oracle.getRoot(), "mirror root == reference oracle root");
  ok(ix.arbiterMode === false && ix.ledger === null, "public mode throughout: no ledger exists");
  const feed = ix.store.allEvents();
  ok(feed.map((e) => e.kind).join(",") === "depositPriv,transferPriv,withdrawPriv,disbursePriv",
    `feed kinds in chain order: ${feed.map((e) => e.kind).join(",")}`);

  step("REGISTRY: mirror reflects the balanced stream; module ops pinned to it");
  ok(ix.modules.isRegistered(MOD_DEP) && ix.modules.isRegistered(MOD_DIS), "registered modules mirrored");
  ok(ix.modules.watchAddresses(ix.kem.pendingModules()).length === 4, "watch-set carries all four registered modules");

  step("FEED: depositPriv entry carries everything S3.6 scanning needs");
  const dep = feed[0];
  ok(dep.epoch === null, "consumer entries carry no arbiter epoch");
  ok(dep.slices.length === 2 && dep.slices[0].leafIndex === 0 && dep.slices[1].leafIndex === 1,
    "two receiver slices with leafIndex annotations");
  ok(dep.ciphertext.length === 8, "8 receiver ct elements (2 outputs x 4)");
  ok(dep.viewTags!.length === 2 && dep.viewTags![0] === dec(sealed0.viewTag), "viewTags ride the entry");
  ok(dep.kemCiphertexts!.length === 2 && dep.kemCiphertexts![0] === kemHex(sealed0.kemCiphertext),
    "per-output kem cts ride the entry (0x-hex)");

  step("S3.6 PIPELINE: viewTag filter -> Decaps -> decrypt -> leaf-match, from the feed alone");
  const scanEcdh = ecdhSharedSecret(VIEW.formattedPrivateKey, [BigInt(dep.ecdhPublicKey![0]), BigInt(dep.ecdhPublicKey![1])]);
  ok(consumerViewTag(scanEcdh) === BigInt(dep.viewTags![0]), "scanner's viewTag recomputation matches slice 0's published tag");
  const opened = openConsumerOutput({
    cipherText: dep.ciphertext.slice(0, 4).map(BigInt),
    ecdhPublicKey: [BigInt(dep.ecdhPublicKey![0]), BigInt(dep.ecdhPublicKey![1])],
    viewPriv: VIEW.formattedPrivateKey,
    kemDk: KEM.secretKey,
    kemCiphertext: Uint8Array.from(Buffer.from(dep.kemCiphertexts![0].slice(2), "hex")),
    encryptionNonce: BigInt(dep.encryptionNonce!),
    index: 0,
  });
  ok(opened.value === value0 && opened.salt === salt0, "decrypt recovers (value, salt)");
  ok(commitment(opened.value, opened.salt, SPEND.publicKey) === oc0, "commitment(value, salt, spendPub) == the tree leaf (leaf-match accept)");

  step("TRANSFER/WITHDRAW: nullifiers join the public set; the announcement attaches");
  ok(new Set(ix.store.nullifiers()).size === 4, "4 nonzero nullifiers (1 transfer + 2 withdraw + 1 disburse; zero pads skipped)");
  const wdr = feed[2];
  ok(wdr.announcement !== undefined && wdr.announcement.ephemeralPub === REAL_R && wdr.announcement.viewTag === 5,
    "withdrawPriv entry carries the module's stealth announcement");
  ok(ix.store.announcements().some((a) => a.txHash === "0xcwdr"), "the /announcements projection includes withdrawPriv");

  step("PUBLIC BATCH FILL: fold-checked disburse serves real interior paths auth-free");
  const dis = feed[3];
  ok(dis.disclosure?.status === "verified", "consumer disclosure fully checks out");
  ok(dis.batchId === disburse.start, "entry carries the batchId (start leaf)");
  ok(dis.viewTags!.join(",") === dTags.map(dec).join(","), "viewTag run rides the entry");
  ok(dis.outputCommitments!.join(",") === dCommits.map(dec).join(","), "commitment run rides the entry");
  const block = disburse.start / B;
  ok(ix.tree.isBatch(block) && ix.tree.isPublicBatch(block), "block tagged as a PUBLIC (consumer) batch");
  for (const i of Array(B).keys()) {
    const p = ix.tree.path(disburse.start + i);
    ok(!("batchLeaf" in p), `path(${disburse.start + i}) is a real interior path`);
  }

  step("KEM CHUNKS: pending -> assembled, keccak-rechecked, out of order");
  ok(ix.kem.pendingModules().has(MOD_DIS.toLowerCase()), "batch incomplete => module in the pending set");
  ok(ix.kem.status(disburse.start, 1_700_000_010, 3600) === "pending", "inside the grace window: kem-pending");
  ok(ix.kem.status(disburse.start, 1_800_000_000, 3600) === "withheld", "past the grace window: kem-withheld");
  // chunk 1 FIRST (permissionless completion arrives in any order)
  sim.tx();
  const c1log = sim.log("DisburseKemChunkAccepted", "0xchunk1", { batchId: BigInt(disburse.start), chunkIndex: 1n, chunkData: chunk1 }, MOD_DIS);
  ix.applyLogs([c1log]);
  ok(ix.kem.assembled(disburse.start) === null, "one chunk in: not yet assembled");
  ok(ix.kem.projection(disburse.start, 1_700_000_010, 3600)!.acceptedCount === 1, "projection counts the accepted chunk");
  sim.tx();
  const c0log = sim.log("DisburseKemChunkAccepted", "0xchunk0", { batchId: BigInt(disburse.start), chunkIndex: 0n, chunkData: chunk0 }, MOD_DIS);
  ix.applyLogs([c0log]);
  const assembled = ix.kem.assembled(disburse.start);
  ok(assembled !== null && assembled.length === B, "all chunks in: per-output kem ct array assembled");
  ok(assembled!.every((ct, i) => ct === dKemCts[i]), "assembled cts equal the chunked originals, leaf order");
  ok(ix.kem.status(disburse.start, 1_800_000_000, 3600) === "complete", "complete beats the grace window");
  ok(!ix.kem.pendingModules().has(MOD_DIS.toLowerCase()), "completed batch drops the module from the pending set");

  step("/events PROJECTION: the disbursePriv entry joins its kem transport state");
  const evRes = await eventsRoute.handle({ ix, tokens: null, params: [], query: new URLSearchParams() });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const evBody = evRes.body as any[];
  const evDis = evBody.find((e) => e.kind === "disbursePriv");
  ok(evDis.kem?.status === "complete" && evDis.kem.kemCiphertexts.length === B,
    "/events serves kem status + the assembled per-output cts");
  ok(evDis.disclosure === "verified", "/events projects the disclosure status string");

  step("REMOVED-MODULE WATCH: a removed disburse module stays watched while a batch is kem-incomplete");
  {
    const sim2 = makeSim();
    const ix2 = makeIndexer();
    const subtreeRoot = sim2.oracle.computeSubtreeRoot(dCommits);
    sim2.tx();
    const start = 0;
    sim2.oracle.attachSubtree(subtreeRoot, dCommits);
    const root = sim2.oracle.getRoot();
    const logs2: ParsedLog[] = [
      ...register(sim2, "0xr", MOD_DIS),
      sim2.log("SubtreeAppended", "0xd", { startLeafIndex: 0n, subtreeRoot, root }),
      sim2.opApplied("0xd", MOD_DIS, { startLeafIndex: start, nullifierCount: 1, leafCount: 0, subtreeRoot, root }),
      sim2.log("DisbursedPriv", "0xd", {
        batchId: 0n, nullifier: 2001n, subtreeRoot, disclosureHash: dh,
        ecdhPublicKey: [1n, 2n], encryptionNonce: 1n, root, kemChunkHashes: chunkHashes,
      }, MOD_DIS),
      sim2.log("DisbursePrivDisclosure", "0xd", { startLeafIndex: 0n, disclosure: dDisclosure }, MOD_DIS),
      ...remove(sim2, "0xrm", MOD_DIS),
    ];
    ix2.applyLogs(logs2);
    ok(!ix2.modules.isRegistered(MOD_DIS), "module removed from the registered set");
    ok(ix2.modules.watchAddresses(ix2.kem.pendingModules()).includes(MOD_DIS.toLowerCase()),
      "REMOVED module stays in the watch-set while its batch is kem-incomplete");
    sim2.tx();
    ix2.applyLogs([
      sim2.log("DisburseKemChunkAccepted", "0xk0", { batchId: 0n, chunkIndex: 0n, chunkData: chunk0 }, MOD_DIS),
      sim2.log("DisburseKemChunkAccepted", "0xk0", { batchId: 0n, chunkIndex: 1n, chunkData: chunk1 }, MOD_DIS),
    ]);
    ok(ix2.modules.watchAddresses(ix2.kem.pendingModules()).length === 0,
      "all chunks accepted => the removed address may finally be dropped");
  }

  step("REPLAY: the whole consumer range converges (feed, registry, kem, tree)");
  ix.applyLogs([...allLogs, c1log, c0log]);
  ok(ix.store.allEvents().length === 4, "feed did not grow on replay");
  ok(ix.tree.root() === sim.oracle.getRoot(), "tree unchanged on replay");
  ok(new Set(ix.store.nullifiers()).size === 4, "nullifier set unchanged on replay");
  ok(ix.kem.assembled(disburse.start)!.length === B, "kem assembly unchanged on replay");

  step("GUARDS: OpApplied disagreement, balanced-stream violations, keccak mismatch all throw");
  {
    const threw = (fn: () => void): string => {
      try {
        fn();
        return "";
      } catch (e) {
        return (e as Error).message;
      }
    };
    // OpApplied claims one leaf where the op appended two.
    const simG = makeSim();
    const ixG = makeIndexer();
    const g0 = simG.appended("0xg", oc0);
    const g1 = simG.appended("0xg", oc1);
    const badOp = [
      ...register(simG, "0xgr", MOD_DEP),
      g0.log, g1.log,
      simG.opApplied("0xg", MOD_DEP, { startLeafIndex: g0.leafIndex, nullifierCount: 0, leafCount: 1, subtreeRoot: 0n, root: g1.root }),
      simG.log("DepositedPriv", "0xg", {
        firstLeafIndex: BigInt(g0.leafIndex), oc0, oc1, amount: 1n,
        ecdhPublicKey: [1n, 2n], ctReceiver0: [1n, 1n, 1n, 1n], ctReceiver1: [2n, 2n, 2n, 2n],
        viewTags: [1n, 2n], encryptionNonce: 1n, root: g1.root,
        kemCiphertexts: [fakeKemCt(9), fakeKemCt(10)],
      }, MOD_DEP),
    ];
    ok(/OpApplied disagrees/.test(threw(() => ixG.applyLogs(badOp))), "an OpApplied disagreeing with the op's tree effects throws");

    // Balanced-stream asserts: fresh double-add / remove-of-unknown.
    const simB = makeSim();
    const ixB = makeIndexer();
    ixB.applyLogs(register(simB, "0xb1", MOD_DEP));
    ok(/double ModuleRegistered/.test(threw(() => ixB.applyLogs(register(simB, "0xb2", MOD_DEP)))),
      "a FRESH double-add throws (the pool reverts no-op transitions)");
    const simB2 = makeSim();
    const ixB2 = makeIndexer();
    ok(/without a live registration/.test(threw(() => ixB2.applyLogs(remove(simB2, "0xb3", MOD_TRF)))),
      "a remove-of-unknown throws");

    // Chunk data whose keccak disagrees with the batch-time commitment.
    const simK = makeSim();
    const ixK = makeIndexer();
    const subtreeRoot = simK.oracle.computeSubtreeRoot(dCommits);
    simK.tx();
    simK.oracle.attachSubtree(subtreeRoot, dCommits);
    const rootK = simK.oracle.getRoot();
    ixK.applyLogs([
      ...register(simK, "0xkr", MOD_DIS),
      simK.log("SubtreeAppended", "0xkd", { startLeafIndex: 0n, subtreeRoot, root: rootK }),
      simK.opApplied("0xkd", MOD_DIS, { startLeafIndex: 0, nullifierCount: 1, leafCount: 0, subtreeRoot, root: rootK }),
      simK.log("DisbursedPriv", "0xkd", {
        batchId: 0n, nullifier: 3001n, subtreeRoot, disclosureHash: dh,
        ecdhPublicKey: [1n, 2n], encryptionNonce: 1n, root: rootK, kemChunkHashes: chunkHashes,
      }, MOD_DIS),
      simK.log("DisbursePrivDisclosure", "0xkd", { startLeafIndex: 0n, disclosure: dDisclosure }, MOD_DIS),
    ]);
    simK.tx();
    ok(/keccak != committed hash/.test(threw(() => ixK.applyLogs([
      simK.log("DisburseKemChunkAccepted", "0xkk", { batchId: 0n, chunkIndex: 0n, chunkData: chunk1 }, MOD_DIS),
    ]))), "chunk bytes hashing differently from the commitment throw (mirror-invariant style)");
  }

  step("TAMPERED DISCLOSURE: mismatch alarms, batch stays a sentinel (no fill)");
  {
    const simT = makeSim();
    const ixT = makeIndexer();
    const subtreeRoot = simT.oracle.computeSubtreeRoot(dCommits);
    simT.tx();
    simT.oracle.attachSubtree(subtreeRoot, dCommits);
    const root = simT.oracle.getRoot();
    const tampered = [...dDisclosure];
    tampered[0] = tampered[0] + 1n; // a receiver ct element flips; dh stays honest
    ixT.applyLogs([
      ...register(simT, "0xtr", MOD_DIS),
      simT.log("SubtreeAppended", "0xtd", { startLeafIndex: 0n, subtreeRoot, root }),
      simT.opApplied("0xtd", MOD_DIS, { startLeafIndex: 0, nullifierCount: 1, leafCount: 0, subtreeRoot, root }),
      simT.log("DisbursedPriv", "0xtd", {
        batchId: 0n, nullifier: 4001n, subtreeRoot, disclosureHash: dh,
        ecdhPublicKey: [1n, 2n], encryptionNonce: 1n, root, kemChunkHashes: chunkHashes,
      }, MOD_DIS),
      simT.log("DisbursePrivDisclosure", "0xtd", { startLeafIndex: 0n, disclosure: tampered }, MOD_DIS),
    ]);
    const e = ixT.store.allEvents()[0];
    ok(e.disclosure?.status === "mismatch", "tampered element => disclosure mismatch alarm");
    ok(ixT.store.getAlarms().length === 1 && ixT.store.getAlarms()[0].status === "mismatch", "alarm joins the channel");
    ok("batchLeaf" in ixT.tree.path(0), "tampered batch is NOT filled — path stays the sentinel");
    ok(!ixT.tree.isPublicBatch(0), "block not tagged public");
  }

  step("BAD FOLD: dh matches the published array but commitments don't fold to subtreeRoot");
  {
    const simF = makeSim();
    const ixF = makeIndexer();
    const subtreeRoot = simF.oracle.computeSubtreeRoot(dCommits); // the PROOF's root (honest)
    simF.tx();
    simF.oracle.attachSubtree(subtreeRoot, dCommits);
    const root = simF.oracle.getRoot();
    const badCommits = [...dCommits];
    badCommits[0] = badCommits[0] + 1n;
    const badDisclosure = consumerDisclosureElements(dCts, dTags, badCommits);
    const badDh = disclosureChain(badDisclosure); // the event's dh COVERS the bad array
    ixF.applyLogs([
      ...register(simF, "0xfr", MOD_DIS),
      simF.log("SubtreeAppended", "0xfd", { startLeafIndex: 0n, subtreeRoot, root }),
      simF.opApplied("0xfd", MOD_DIS, { startLeafIndex: 0, nullifierCount: 1, leafCount: 0, subtreeRoot, root }),
      simF.log("DisbursedPriv", "0xfd", {
        batchId: 0n, nullifier: 5001n, subtreeRoot, disclosureHash: badDh,
        ecdhPublicKey: [1n, 2n], encryptionNonce: 1n, root, kemChunkHashes: chunkHashes,
      }, MOD_DIS),
      simF.log("DisbursePrivDisclosure", "0xfd", { startLeafIndex: 0n, disclosure: badDisclosure }, MOD_DIS),
    ]);
    const e = ixF.store.allEvents()[0];
    ok(e.disclosure?.status === "mismatch", "bad-fold publish => mismatch alarm, not a 500");
    ok(e.disclosure?.expected === subtreeRoot.toString(), "alarm's expected == the on-chain subtreeRoot (check 3)");
    ok("batchLeaf" in ixF.tree.path(0), "bad-fold batch is NOT filled");
  }

  step("ADDRESS GATE: forged pool-family events from a watched module are dropped; pool-emitted still apply");
  {
    const simA = makeSim();
    const ixA = makeIndexer();
    ixA.applyLogs(register(simA, "0xar", MOD_DEP)); // pool-emitted: MOD_DEP is watched
    const rootBefore = ixA.tree.root();
    const nliBefore = ixA.tree.nextLeafIndex();
    const ATTACKER = "0x" + "aa".repeat(20);
    simA.tx();
    // Every one of these decodes as a pool/factory event name but is EMITTED by
    // the watched module — the gate must drop them all without a throw.
    ixA.applyLogs([
      simA.log("Appended", "0xatk", { leafIndex: 0n, leaf: 123n, root: 456n }, MOD_DEP),
      simA.log("ModuleRegistered", "0xatk", { module: ATTACKER }, MOD_DEP),
      simA.log("Deposited", "0xatk", { oc0: 1n, oc1: 2n }, MOD_DEP),
      simA.log("Swept", "0xatk", { salt: "0x" + "11".repeat(32), sweeper: ATTACKER, amount: 1n }, MOD_DEP),
      // ...and a consumer event from an UNWATCHED address is not ours either.
      simA.log("DepositedPriv", "0xatk2", { firstLeafIndex: 0n, oc0: 1n, oc1: 2n }, ATTACKER),
    ]);
    ok(ixA.tree.root() === rootBefore && ixA.tree.nextLeafIndex() === nliBefore,
      "forged module-emitted Appended did not move the mirror");
    ok(!ixA.modules.isKnown(ATTACKER), "forged module-emitted ModuleRegistered did not reach the registry mirror");
    ok(ixA.store.allEvents().length === 0, "forged Deposited / unwatched DepositedPriv did not reach the feed");
    // The same names EMITTED BY THE POOL still apply.
    simA.tx();
    const pa0 = simA.appended("0xok", oc0);
    const pa1 = simA.appended("0xok", oc1);
    ixA.applyLogs([pa0.log, pa1.log, simA.log("Deposited", "0xok", { oc0, oc1 })]);
    ok(ixA.tree.root() === simA.oracle.getRoot(), "pool-emitted Appended pair applied to the mirror");
    ok(ixA.store.allEvents().length === 1 && ixA.store.allEvents()[0].kind === "deposit",
      "pool-emitted Deposited landed on the feed");
  }

  step("OPAPPLIED DRAIN: an unconsumed OpApplied warns (alarm-class) and never wedges ingest");
  {
    const simD = makeSim();
    const ixD = makeIndexer();
    const warns: string[] = [];
    const origWarn = console.warn;
    console.warn = (...a: unknown[]): void => {
      warns.push(a.map(String).join(" "));
    };
    try {
      ixD.applyLogs(register(simD, "0xdr", MOD_DEP));
      simD.tx();
      // A pool-emitted OpApplied whose module never emitted a decodable family
      // event: the tree still advances on the pool's Appended, and the anchor
      // gap must surface as a warning, not a throw.
      const a0 = simD.appended("0xlone", oc0);
      ixD.applyLogs([
        a0.log,
        simD.opApplied("0xlone", MOD_DEP, { startLeafIndex: a0.leafIndex, nullifierCount: 0, leafCount: 1, subtreeRoot: 0n, root: a0.root }),
      ]);
    } finally {
      console.warn = origWarn;
    }
    ok(warns.some((w) => /ALARM OpApplied unconsumed/.test(w) && w.includes(MOD_DEP.toLowerCase()) && w.includes("0xlone")),
      "the alarm-class warning names the module and tx");
    ok(ixD.tree.root() === simD.oracle.getRoot(), "the mirror advanced on the pool tree events regardless");
    // Not wedged: a later range still ingests.
    simD.tx();
    const a1 = simD.appended("0xafter", oc1);
    ixD.applyLogs([a1.log]);
    ok(ixD.tree.root() === simD.oracle.getRoot(), "a subsequent range still applies (no wedge)");
  }

  step("KEM DEGRADE: module-emitted chunk inconsistencies warn + drop; ingest continues");
  {
    const simM = makeSim();
    const ixM = makeIndexer();
    const subtreeRoot = simM.oracle.computeSubtreeRoot(dCommits);
    simM.tx();
    simM.oracle.attachSubtree(subtreeRoot, dCommits);
    const rootM = simM.oracle.getRoot();
    ixM.applyLogs([
      ...register(simM, "0xmr", MOD_DIS),
      simM.log("SubtreeAppended", "0xmd", { startLeafIndex: 0n, subtreeRoot, root: rootM }),
      simM.opApplied("0xmd", MOD_DIS, { startLeafIndex: 0, nullifierCount: 1, leafCount: 0, subtreeRoot, root: rootM }),
      simM.log("DisbursedPriv", "0xmd", {
        batchId: 0n, nullifier: 6001n, subtreeRoot, disclosureHash: dh,
        ecdhPublicKey: [1n, 2n], encryptionNonce: 1n, root: rootM, kemChunkHashes: chunkHashes,
      }, MOD_DIS),
      simM.log("DisbursePrivDisclosure", "0xmd", { startLeafIndex: 0n, disclosure: dDisclosure }, MOD_DIS),
    ]);
    simM.tx();
    // None of these may throw: an unknown batch, an out-of-range index — a
    // throw would wedge the poll loop forever on one hostile module emission.
    ixM.applyLogs([
      simM.log("DisburseKemChunkAccepted", "0xbogus1", { batchId: 999n, chunkIndex: 0n, chunkData: chunk0 }, MOD_DIS),
      simM.log("DisburseKemChunkAccepted", "0xbogus2", { batchId: 0n, chunkIndex: 5n, chunkData: chunk0 }, MOD_DIS),
    ]);
    ok(ixM.kem.projection(0, 1_700_000_010, 3600)!.acceptedCount === 0, "bogus accepts counted nothing");
    // Subsequent VALID ingest proceeds — the whole point of degrading.
    simM.tx();
    ixM.applyLogs([
      simM.log("DisburseKemChunkAccepted", "0xv0", { batchId: 0n, chunkIndex: 0n, chunkData: chunk0 }, MOD_DIS),
      simM.log("DisburseKemChunkAccepted", "0xv1", { batchId: 0n, chunkIndex: 1n, chunkData: chunk1 }, MOD_DIS),
    ]);
    ok(ixM.kem.assembled(0) !== null, "valid chunk accepts after the bogus ones still assemble");
    // A duplicate accept from a FRESH tx (the shipped module would revert it)
    // is dropped too, leaving the assembled state alone.
    simM.tx();
    ixM.applyLogs([
      simM.log("DisburseKemChunkAccepted", "0xdup", { batchId: 0n, chunkIndex: 0n, chunkData: chunk1 }, MOD_DIS),
    ]);
    ok(ixM.kem.assembled(0)!.every((ct, i) => ct === dKemCts[i]), "duplicate accept dropped; assembly unchanged");
  }

  step("ACCEPTED-UNASSEMBLED: all chunks accepted but bytes undecodable is a distinct status, not withheld");
  {
    const simU = makeSim();
    const ixU = makeIndexer();
    const subtreeRoot = simU.oracle.computeSubtreeRoot(dCommits);
    simU.tx();
    simU.oracle.attachSubtree(subtreeRoot, dCommits);
    const rootU = simU.oracle.getRoot();
    ixU.applyLogs([
      ...register(simU, "0xur", MOD_DIS),
      simU.log("SubtreeAppended", "0xud", { startLeafIndex: 0n, subtreeRoot, root: rootU }),
      simU.opApplied("0xud", MOD_DIS, { startLeafIndex: 0, nullifierCount: 1, leafCount: 0, subtreeRoot, root: rootU }),
      simU.log("DisbursedPriv", "0xud", {
        batchId: 0n, nullifier: 7001n, subtreeRoot, disclosureHash: dh,
        ecdhPublicKey: [1n, 2n], encryptionNonce: 1n, root: rootU, kemChunkHashes: chunkHashes,
      }, MOD_DIS),
      simU.log("DisbursePrivDisclosure", "0xud", { startLeafIndex: 0n, disclosure: dDisclosure }, MOD_DIS),
    ]);
    // chunk 0 accepted with UNDECODABLE calldata (chunkData null): one chunk is
    // still genuinely missing on-chain, so past the grace window the batch
    // reads withheld, exactly as before.
    simU.tx();
    ixU.applyLogs([
      simU.log("DisburseKemChunkAccepted", "0xu0", { batchId: 0n, chunkIndex: 0n, chunkData: null }, MOD_DIS),
    ]);
    ok(ixU.kem.status(0, 1_800_000_000, 3600) === "withheld", "one accept missing on-chain: still withheld past grace");
    // chunk 1 accepted, also undecodable: NOW every accept landed — nothing was
    // withheld — the batch reads accepted-unassembled regardless of the grace.
    ixU.applyLogs([
      simU.log("DisburseKemChunkAccepted", "0xu1", { batchId: 0n, chunkIndex: 1n, chunkData: null }, MOD_DIS),
    ]);
    ok(ixU.kem.status(0, 1_800_000_000, 3600) === "accepted-unassembled",
      "all accepted + bytes missing => accepted-unassembled (not withheld), grace-independent");
    const proj = ixU.kem.projection(0, 1_800_000_000, 3600)!;
    ok(proj.status === "accepted-unassembled" && proj.acceptedCount === 2 && proj.kemCiphertexts === undefined,
      "projection counts both accepts and serves no assembled cts");
    // The recovery path (what boot's re-fetch calls): attach the real bytes —
    // keccak-checked — and the batch completes; wrong bytes throw (RPC lied).
    const badAttach = ((): string => {
      try {
        ixU.kem.attachChunkData(0, 1, chunk0);
        return "";
      } catch (e) {
        return (e as Error).message;
      }
    })();
    ok(/keccak != committed hash/.test(badAttach), "attaching wrong re-fetched bytes throws (fetched-calldata posture)");
    ixU.kem.attachChunkData(0, 0, chunk0);
    ixU.kem.attachChunkData(0, 1, chunk1);
    ok(ixU.kem.status(0, 1_800_000_000, 3600) === "complete" && ixU.kem.assembled(0)!.length === B,
      "re-fetched bytes complete the batch (the boot recovery expectation)");
  }

  console.log(`\n${failures.count === 0 ? "CONSUMER UNIT TEST PASS — registry mirror + watch rule, address-gated dispatch, S3.6 pipeline off the feed, OpApplied anchor + drain, public batch fill, kem chunk assembly + degrade + accepted-unassembled, alarms" : `CONSUMER UNIT TEST FAIL — ${failures.count} assertion(s)`}`);
  process.exit(failures.count === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nCONSUMER UNIT TEST ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
