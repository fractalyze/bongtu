// Ingest correlation-ladder unit test — ANVIL-FREE, no proofs, no RPC.
//
// Drives `Indexer.applyLogs` with synthetic ParsedLog sequences: the test plays
// the chain (a reference `ImtTree` supplies every event's carried root) and
// builds REAL envelope ciphertext with the sdk's poseidonEncrypt, so the
// arbiter ledger legs decrypt genuine bytes — only proving and provider I/O are
// absent. Covers what the multi-minute anvil gate cannot cheaply reach:
//   - one multicall tx carrying TWO transfers (the ordered per-tx pair queues);
//   - a Transferred whose commitment != its Appended leaf (correlation throw);
//   - a replayed log range (must converge, not double feed/notes/nullifiers);
//   - Disbursed with and without its DisburseCiphertexts log (withheld feed
//     entry + alarm; the ledger only opens published batches);
//   - PostgresLedger's own (txHash, logIndex) replay dedup;
//   - pollOnce failure/success state + the /health projection of it.
//
// Preconditions shared with src/chain.ts: ethers loadable from
// BONGTU_NODE_MODULES and contracts/out built (the Indexer constructor reads the
// pool ABI). The dummy RPC below is never contacted.
//
//   node --import tsx test/ingest.test.ts       # (== npm run test:ingest)

import { deriveKeypair, commitment, poseidonEncrypt, ecdhSharedSecret } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import {
  ml_kem768,
  kemSsToLimbs,
  kemBindingOf,
  kemBytesToHex,
  hybridEnvelopeKey,
} from "@bongtu/core/kem";
import { ImtTree } from "@bongtu/core/imt";
import type { Pool } from "pg";
import { MirrorTree } from "../src/tree.js";
import { type OpEnvelope } from "../src/ledger.js";
import { PostgresLedger } from "../src/postgres.js";
import { Indexer, type ParsedLog } from "../src/ingest.js";
import { ethers, abiKnowsKem } from "../src/chain.js";
import { disclosureChain } from "@bongtu/core/envelope";
import { health } from "../src/api/routes/health.js";

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
function step(t: string): void {
  console.log(`\n=== ${t} ===`);
}

// H is free here (applyLogs never consults ingest's module constant — the test
// injects the MirrorTree), so use a small tree for cheap naive folds.
const H = 8;
const B = 4;

const DUMMY_RPC = "http://127.0.0.1:1"; // never contacted
const DUMMY_POOL = "0x" + "12".repeat(20);

const ARB = deriveKeypair(555555555555555555555555n);
// Deterministic arbiter ML-KEM keypair + a per-label encapsulation, for the V2
// (hybrid-envelope) legs — the V1 legs deliberately carry NO kem material.
const ARB_KEM = ml_kem768.keygen(new Uint8Array(64).fill(21));
function kemDraw(seedByte: number): { limbs: [bigint, bigint]; binding: bigint; ciphertextHex: string } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(
    ARB_KEM.publicKey,
    new Uint8Array(32).fill(seedByte),
  );
  const limbs = kemSsToLimbs(sharedSecret);
  return { limbs, binding: kemBindingOf(limbs), ciphertextHex: kemBytesToHex(cipherText) };
}
const EMP = deriveKeypair(111111111111111111111111n);
const U1 = deriveKeypair(222222222222222222222222n);
const U2 = deriveKeypair(333333333333333333333333n);
const U3 = deriveKeypair(444444444444444444444444n);
const RCPTS = Array.from({ length: B }, (_, i) => deriveKeypair(2000000011n + BigInt(i) * 1000003n));

const pub2 = (k: Keypair): [bigint, bigint] => [k.publicKey[0], k.publicKey[1]];

interface NoteSpec {
  owner: Keypair;
  v: bigint;
  s: bigint;
}
const note = (owner: Keypair, v: bigint, s: bigint): NoteSpec => ({ owner, v, s });
const commitOf = (n: NoteSpec): bigint => commitment(n.v, n.s, n.owner.publicKey);

/**
 * A synthetic chain: owns the reference ImtTree (source of every event's
 * carried root), block/logIndex counters, and the per-op log builders. Each
 * builder emits the exact event shapes ingest consumes, with envelope bytes
 * encrypted to ARB the way the circuits lay them out (the @bongtu/core/envelope
 * layout table — hand-assembled HERE on purpose, as an independent check of
 * the shared codec).
 */
function makeSim() {
  const oracle = new ImtTree(H, B);
  let blockNumber = 0;
  let logIndex = 0;
  const tx = (): void => {
    blockNumber++;
    logIndex = 0;
  };
  const log = (name: string, txHash: string, args: Record<string, unknown>): ParsedLog => ({
    name,
    blockNumber,
    logIndex: logIndex++,
    txHash,
    // Synthetic block time: monotonic in block order (anvil/live blocks carry a
    // real one; the ingest history feed only needs a per-block unix-seconds stamp).
    blockTimestamp: 1_700_000_000 + blockNumber,
    args,
  });
  const appended = (txHash: string, leaf: bigint): ParsedLog => {
    const leafIndex = oracle.getNextLeafIndex();
    oracle.appendLeaf(leaf);
    return log("Appended", txHash, { leafIndex: BigInt(leafIndex), leaf, root: oracle.getRoot() });
  };

  // `kem` switches the builder to the V2 (hybrid) event shape: the envelope is
  // encrypted under the tagged hybrid key and the log grows kemBinding +
  // kemCiphertext. `kem.ciphertextHex` may be a DIFFERENT encapsulation than
  // `kem.limbs` (the consistent-but-junk-ct attack) — the binding always
  // matches the limbs the envelope was keyed with, like a real proof's output.
  const deposit = (
    txHash: string,
    o0: NoteSpec,
    o1: NoteSpec,
    eph: bigint,
    nonce: bigint,
    kem?: { limbs: [bigint, bigint]; ciphertextHex: string },
  ): ParsedLog[] => {
    tx();
    const [c0, c1] = [commitOf(o0), commitOf(o1)];
    const out = [appended(txHash, c0), appended(txHash, c1)];
    const plain = [...pub2(o0.owner), ...pub2(o1.owner), o0.v, o0.s, o1.v, o1.s];
    const shared = ecdhSharedSecret(eph, ARB.publicKey);
    const key = kem ? hybridEnvelopeKey(shared, kem.limbs) : shared;
    out.push(
      log("Deposited", txHash, {
        oc0: c0,
        oc1: c1,
        ecdhPublicKey: pub2(deriveKeypair(eph)),
        encryptedValuesForAuthority: poseidonEncrypt(plain, key, nonce),
        encryptionNonce: nonce,
        ...(kem ? { kemBinding: kemBindingOf(kem.limbs), kemCiphertext: kem.ciphertextHex } : {}),
      }),
    );
    return out;
  };

  // `sameTx` lets a second transfer join the previous tx (multicall shape);
  // in0.owner is the single input owner the envelope layout carries.
  const transfer = (
    txHash: string,
    in0: NoteSpec,
    in1: NoteSpec,
    o0: NoteSpec,
    o1: NoteSpec,
    eph: bigint,
    nonce: bigint,
    nfs: [bigint, bigint],
    sameTx = false,
  ): ParsedLog[] => {
    if (!sameTx) tx();
    const [c0, c1] = [commitOf(o0), commitOf(o1)];
    const out = [appended(txHash, c0), appended(txHash, c1)];
    const plain = [
      ...pub2(in0.owner), in0.v, in0.s, in1.v, in1.s,
      ...pub2(o0.owner), ...pub2(o1.owner), o0.v, o0.s, o1.v, o1.s,
    ];
    out.push(
      log("Transferred", txHash, {
        outputCommitments: [c0, c1],
        nullifiers: nfs,
        epoch: 1n,
        ecdhPublicKey: pub2(deriveKeypair(eph)),
        encryptedValuesForReceiver0: poseidonEncrypt([o0.v, o0.s], ecdhSharedSecret(eph, o0.owner.publicKey), nonce),
        encryptedValuesForReceiver1: poseidonEncrypt([o1.v, o1.s], ecdhSharedSecret(eph, o1.owner.publicKey), nonce),
        encryptedValuesForAuthority: poseidonEncrypt(plain, ecdhSharedSecret(eph, ARB.publicKey), nonce),
        encryptionNonce: nonce,
      }),
    );
    return out;
  };

  const disburse = (
    txHash: string,
    input: NoteSpec,
    outs: NoteSpec[],
    eph: bigint,
    nonce: bigint,
    nf: bigint,
    publish: "full" | "none",
  ): { logs: ParsedLog[]; start: number; commits: bigint[] } => {
    tx();
    const commits = outs.map(commitOf);
    const sub = oracle.computeSubtreeRoot(commits);
    const start = Math.ceil(oracle.getNextLeafIndex() / B) * B; // attach pads to the boundary
    oracle.attachSubtree(sub, commits);
    const logs = [log("SubtreeAppended", txHash, { startLeafIndex: BigInt(start), subtreeRoot: sub, root: oracle.getRoot() })];
    let dh = 987654321n; // committed in the proof even when nothing is published
    let full: bigint[] | null = null;
    if (publish === "full") {
      const rcpt = outs.flatMap((o) => poseidonEncrypt([o.v, o.s], ecdhSharedSecret(eph, o.owner.publicKey), nonce));
      const plain = [
        ...pub2(input.owner), input.v, input.s,
        ...outs.flatMap((o) => pub2(o.owner)),
        ...outs.flatMap((o) => [o.v, o.s]),
      ];
      full = [...rcpt, ...poseidonEncrypt(plain, ecdhSharedSecret(eph, ARB.publicKey), nonce)];
      dh = disclosureChain(full);
    }
    logs.push(
      log("Disbursed", txHash, {
        subtreeRoot: sub,
        epoch: 1n,
        ecdhPublicKey: pub2(deriveKeypair(eph)),
        encryptionNonce: nonce,
        nullifier: nf,
        disclosureHash: dh,
      }),
    );
    if (full) logs.push(log("DisburseCiphertexts", txHash, { startLeafIndex: BigInt(start), receiverCiphertexts: full }));
    return { logs, start, commits };
  };

  return { oracle, deposit, transfer, disburse };
}

// PostgresLedger is the ONLY ledger (Postgres-only, U-I4); its apply/notesOf/
// historyOf read model never touches SQL (only boot()/flushInto() do, and this
// anvil-free test calls neither), so a never-used dummy pool is safe here.
const DUMMY_PG_POOL = null as unknown as Pool;

function makeIndexer(arbiter: boolean, kemSecret: Uint8Array | null = null): Indexer {
  const ix = new Indexer({ rpc: DUMMY_RPC, pool: DUMMY_POOL, startBlock: 0, authorityKey: arbiter ? ARB.formattedPrivateKey : null });
  ix.batchSize = B;
  ix.tree = new MirrorTree(H, B);
  if (arbiter) ix.ledger = new PostgresLedger(DUMMY_PG_POOL, ARB.formattedPrivateKey, kemSecret, B, ix.tree);
  return ix;
}

async function main(): Promise<void> {
  // ---- scenario: deposit → multicall(2 transfers) → disburse(full) →
  // disburse(withheld), all against ONE arbiter-mode indexer -----------------
  const sim = makeSim();
  const ix = makeIndexer(true);

  const dep0 = note(EMP, 30n, 1001n);
  const dep1 = note(EMP, 20n, 1002n);
  const t1o0 = note(U1, 12n, 2001n);
  const t1o1 = note(EMP, 18n, 2002n);
  const t2o0 = note(U2, 5n, 2003n);
  const t2o1 = note(U3, 15n, 2004n);
  const dOuts = RCPTS.map((r, i) => note(r, 3n, 3001n + BigInt(i)));
  const wOuts = [note(RCPTS[0], 2n, 3101n), note(RCPTS[1], 1n, 3102n), note(RCPTS[2], 1n, 3103n), note(RCPTS[3], 1n, 3104n)];

  const logs: ParsedLog[] = [
    ...sim.deposit("0xdep", dep0, dep1, 600000000000000000007n, 555555555555n),
    // MULTICALL: two transfers in ONE tx — Transferred #1 must consume the
    // first two Appended of the tx, #2 the next two (ordered per-tx queues).
    ...sim.transfer("0xmulti", dep0, note(EMP, 0n, 9001n), t1o0, t1o1, 800000000000000000003n, 222222222222n, [101n, 0n]),
    ...sim.transfer("0xmulti", dep1, note(EMP, 0n, 9002n), t2o0, t2o1, 810000000000000000009n, 232323232323n, [102n, 0n], true),
  ];
  const d1 = sim.disburse("0xdis1", t1o0, dOuts, 700000000000000000001n, 111111111111n, 103n, "full");
  const d2 = sim.disburse("0xdis2", t2o0, wOuts, 710000000000000000013n, 121212121212n, 104n, "none");
  logs.push(...d1.logs, ...d2.logs);

  step("APPLY: full synthetic sequence (arbiter mode)");
  ix.applyLogs(logs);
  ok(ix.tree.root() === sim.oracle.getRoot(), "mirror root == reference oracle root");
  ok(ix.tree.nextLeafIndex() === 16, `mirror nextLeafIndex == 16 (got ${ix.tree.nextLeafIndex()})`);

  const feed = ix.store.allEvents();
  const kinds = feed.map((e) => e.kind).join(",");
  ok(kinds === "deposit,transfer,transfer,disburse,disburse", `feed kinds in chain order: ${kinds}`);

  step("MULTICALL: two transfers in one tx correlate to their own leaf pairs");
  const [tf1, tf2] = [feed[1], feed[2]];
  ok(tf1.txHash === "0xmulti" && tf2.txHash === "0xmulti", "both transfer entries share the multicall tx");
  ok(tf1.logIndex !== tf2.logIndex, "distinct logIndex per op in the tx");
  ok(tf1.slices[0].leafIndex === 2 && tf1.slices[1].leafIndex === 3, "transfer #1 outputs landed @2,@3");
  ok(tf2.slices[0].leafIndex === 4 && tf2.slices[1].leafIndex === 5, "transfer #2 outputs landed @4,@5");
  ok(new Set(ix.store.nullifiers()).size === 4, "nullifier set = the 4 nonzero nullifiers (0 pads skipped)");

  step("LEDGER: envelopes recorded notes + spent transitions across the ladder");
  const empNotes = ix.ledger!.notesOf(EMP.publicKey[0], EMP.publicKey[1]);
  ok(empNotes.filter((n) => [0, 1].includes(n.leafIndex) && n.spent).length === 2, "both deposit notes spent by the multicall transfers");
  const u1Notes = ix.ledger!.notesOf(U1.publicKey[0], U1.publicKey[1]);
  ok(u1Notes.length === 1 && u1Notes[0].spent === true, "U1's transfer note spent by the published disburse");
  const u2Notes = ix.ledger!.notesOf(U2.publicKey[0], U2.publicKey[1]);
  ok(u2Notes.length === 1 && u2Notes[0].spent === false, "U2's note NOT spent — the withheld disburse's envelope was never opened");
  const r0Notes = ix.ledger!.notesOf(RCPTS[0].publicKey[0], RCPTS[0].publicKey[1]);
  ok(r0Notes.length === 1 && r0Notes[0].leafIndex === d1.start && r0Notes[0].value === "3", "recipient#0 batch note recorded from the authority tail");

  step("HISTORY: a 2-payee transfer yields one 'sent' PER non-self output (not one merged item)");
  // transfer#2 pays U2(5) AND U3(15) — two independent non-self payees. The
  // employer's history must carry BOTH, never a single collapsed 20→U2 item.
  const empHist = ix.ledger!.historyOf(EMP.publicKey[0], EMP.publicKey[1]);
  const empSent = empHist.filter((h) => h.kind === "sent");
  const sentTo = (kp: typeof U2): string | undefined =>
    empSent.find((h) => h.counterparty === packPubkey(kp.publicKey))?.amount;
  ok(sentTo(U1) === "12", "employer 'sent' 12 to U1 (transfer#1)");
  ok(sentTo(U2) === "5", "employer 'sent' 5 to U2 (transfer#2, split payee A)");
  ok(sentTo(U3) === "15", "employer 'sent' 15 to U3 (transfer#2, split payee B) — NOT merged into U2");
  ok(empSent.length === 3, "exactly three 'sent' items (12→U1, 5→U2, 15→U3), no collapsed item");
  const u3Hist = ix.ledger!.historyOf(U3.publicKey[0], U3.publicKey[1]);
  ok(
    u3Hist.some((h) => h.kind === "received" && h.amount === "15" && h.counterparty === packPubkey(EMP.publicKey)),
    "U3 'received' 15 from the employer",
  );

  step("DISBURSE: published batch opens; withheld batch stays a sentinel + alarms");
  ok(feed[3].disclosure?.status === "verified", "published disburse disclosure checks out");
  ok(feed[4].disclosure?.status === "withheld", "ciphertext-less disburse → withheld feed entry");
  ok(feed[4].slices.length === 0 && feed[4].ciphertext.length === 0, "withheld entry carries no slices/ciphertext");
  ok(ix.store.getAlarms().length === 1 && ix.store.getAlarms()[0].status === "withheld", "withheld joins the alarm channel");
  ok(ix.ledger!.getEnvelopeAlarms().length === 0, "no envelope alarms — every opened envelope cross-checked");
  ok(!("batchLeaf" in ix.tree.path(d1.start)), "path into the ledger-filled batch is a real path");
  ok("batchLeaf" in ix.tree.path(d2.start), "path into the unopened (withheld) batch returns the sentinel");

  step("V1 HISTORY: pre-KEM (kem-less) events decode via the legacy ECDH path — zero false alarms");
  // Every op above is V1-shaped (no kemBinding/kemCiphertext on any args), so
  // the ledger must have taken the legacy raw-ECDH branch for ALL of them: the
  // notes/history assertions above prove decryption worked, and no KEM check
  // may fire on history (pq-envelope-design.md §5 pre-KEM gate).
  ok(logs.every((l) => l.args.kemBinding === undefined), "the scenario is entirely V1-shaped");
  ok(ix.ledger!.getEnvelopeAlarms().length === 0, "V1 history produced ZERO envelope alarms (no kem false-positives)");
  ok(ix.ledger!.notesOf(RCPTS[0].publicKey[0], RCPTS[0].publicKey[1]).length === 1,
    "V1 envelopes still decrypt (kem: null -> legacy key)");

  step("REPLAY: re-applying the same range converges without doubling");
  ix.applyLogs(logs);
  ok(ix.store.allEvents().length === 5, "feed did not grow on replay");
  ok(ix.tree.root() === sim.oracle.getRoot() && ix.tree.nextLeafIndex() === 16, "tree unchanged on replay");
  ok(new Set(ix.store.nullifiers()).size === 4, "nullifier set unchanged on replay");
  ok(ix.ledger!.notesOf(EMP.publicKey[0], EMP.publicKey[1]).length === empNotes.length, "ledger notes did not double on replay");
  ok(ix.store.getAlarms().length === 1, "alarm channel did not double on replay");

  step("GUARD: a Transferred whose commitment != its Appended leaf throws");
  {
    const sim2 = makeSim();
    const ix2 = makeIndexer(false);
    const bad = [
      ...sim2.deposit("0xa", dep0, dep1, 620000000000000000003n, 111n),
      ...sim2.transfer("0xb", dep0, note(EMP, 0n, 9001n), t1o0, t1o1, 630000000000000000011n, 222n, [201n, 0n]),
    ];
    const transferred = bad.find((l) => l.name === "Transferred")!;
    (transferred.args.outputCommitments as bigint[])[0] += 1n;
    let msg = "";
    try {
      ix2.applyLogs(bad);
    } catch (e) {
      msg = (e as Error).message;
    }
    ok(/commitment != Appended leaf/.test(msg), `correlation cross-check threw (got: ${msg || "no throw"})`);
  }

  step("LEDGER: apply() dedups on (txHash, logIndex) by itself");
  {
    const led = new PostgresLedger(DUMMY_PG_POOL, ARB.formattedPrivateKey, null, B, new MirrorTree(H, B));
    const own = deriveKeypair(777777777777777777777777n);
    const [o0, o1] = [note(own, 42n, 4242n), note(own, 0n, 4243n)];
    const eph = 880000000000000000001n;
    const plain = [...pub2(own), ...pub2(own), o0.v, o0.s, o1.v, o1.s];
    const env: OpEnvelope = {
      kind: "deposit",
      txHash: "0xledger",
      logIndex: 7,
      blockTimestamp: 1_700_000_000,
      ecdhPublicKey: pub2(deriveKeypair(eph)),
      nonce: 99n,
      authorityCt: poseidonEncrypt(plain, ecdhSharedSecret(eph, ARB.publicKey), 99n),
      kem: null,
      outputLeaves: [
        { leafIndex: 0, commitment: commitOf(o0) },
        { leafIndex: 1, commitment: commitOf(o1) },
      ],
    };
    led.apply(env);
    led.apply(env);
    ok(led.notesOf(own.publicKey[0], own.publicKey[1]).length === 2, "same envelope applied twice → the two outputs recorded once");
    led.apply({ ...env, logIndex: 8 });
    ok(led.notesOf(own.publicKey[0], own.publicKey[1]).length === 4, "same tx, different logIndex = a distinct op (key is txHash:logIndex)");
  }

  step("DUAL ABI: the pool interface parses BOTH V1 and V2 raw event encodings");
  {
    // Encode a raw log under each vintage's own single-ABI interface, then parse
    // with the indexer's combined interface (what getLogsChunked dispatches on):
    // topic0 differs between vintages, so a V2-only interface would drop V1
    // history on the floor — the silent-skip failure the dual ABI closes.
    const iface = ix.pool.interface;
    ok(abiKnowsKem(iface), "combined interface models the V2 (kemCiphertext) events");
    const v1Iface = new ethers.utils.Interface([
      "event Deposited(uint256 indexed epoch, uint256 firstLeafIndex, uint256 oc0, uint256 oc1, uint256 amount, uint256[2] ecdhPublicKey, uint256[10] encryptedValuesForAuthority, uint256 encryptionNonce, uint256 root)",
    ]);
    const v1Raw = v1Iface.encodeEventLog(v1Iface.getEvent("Deposited"), [
      1n, 0n, 11n, 12n, 5n, [1n, 2n], new Array(10).fill(3n), 42n, 99n,
    ]);
    const v1Parsed = iface.parseLog({ topics: v1Raw.topics, data: v1Raw.data });
    ok(v1Parsed.name === "Deposited" && v1Parsed.args.kemBinding === undefined,
      "a V1-encoded Deposited parses under the combined ABI, WITHOUT kem fields (-> kem: null)");
    const v2Frag = Object.values(iface.events).find(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (e: any) => e.name === "Deposited" && e.inputs.some((i: any) => i.name === "kemCiphertext"),
    )!;
    const v2Raw = iface.encodeEventLog(v2Frag, [
      1n, 0n, 11n, 12n, 5n, [1n, 2n], new Array(10).fill(3n), 42n, 99n, 77n, "0x" + "ab".repeat(1088),
    ]);
    const v2Parsed = iface.parseLog({ topics: v2Raw.topics, data: v2Raw.data });
    ok(v2Parsed.name === "Deposited" && v2Parsed.args.kemBinding !== undefined
      && ethers.utils.arrayify(v2Parsed.args.kemCiphertext).length === 1088,
      "a V2-encoded Deposited parses with kemBinding + a 1088-byte kemCiphertext");
    ok(v1Raw.topics[0] !== v2Raw.topics[0], "V1/V2 topic0 differ (the reason dual-ABI is required)");
  }

  step("V2 KEM: hybrid envelopes decapsulate + binding-check; a junk ct alarms and withholds");
  {
    const simK = makeSim();
    const ixK = makeIndexer(true, ARB_KEM.secretKey);
    const good = kemDraw(31);
    const junk = kemDraw(32); // a DIFFERENT (valid) encapsulation — its ss cannot match the witness limbs
    const gNotes = [note(U1, 40n, 5001n), note(U1, 0n, 5002n)];
    const bNotes = [note(U2, 25n, 5003n), note(U2, 0n, 5004n)];
    const kLogs: ParsedLog[] = [
      // honest V2 deposit: ct matches the limbs the envelope was keyed with
      ...simK.deposit("0xkemgood", gNotes[0], gNotes[1], 640000000000000000005n, 777n, {
        limbs: good.limbs,
        ciphertextHex: good.ciphertextHex,
      }),
      // consistent-but-junk ct (design doc §6): proof-side binding matches its
      // OWN witness limbs, but the submitted ct decapsulates to different ss
      ...simK.deposit("0xkemjunk", bNotes[0], bNotes[1], 660000000000000000009n, 778n, {
        limbs: good.limbs,
        ciphertextHex: junk.ciphertextHex,
      }),
    ];
    ixK.applyLogs(kLogs);

    const u1k = ixK.ledger!.notesOf(U1.publicKey[0], U1.publicKey[1]);
    ok(u1k.length === 2, "matching V2 op: hybrid envelope decrypted, both notes recorded");
    const kemAlarms = ixK.ledger!.getEnvelopeAlarms();
    ok(kemAlarms.length === 1, "exactly one envelope alarm (the junk-wrapped ct)");
    ok(kemAlarms[0].txHash === "0xkemjunk" && /kem binding mismatch/.test(kemAlarms[0].detail),
      "alarm names the tx + 'kem binding mismatch — envelope withheld'");
    ok(kemAlarms[0].expected === kemBindingOf(good.limbs).toString(), "alarm carries the on-chain kemBinding as expected");
    ok(kemAlarms[0].recomputed !== kemAlarms[0].expected, "alarm carries the mismatching recomputed binding");
    ok(ixK.ledger!.notesOf(U2.publicKey[0], U2.publicKey[1]).length === 0,
      "the mismatching op is STOPPED — no notes recorded, envelope withheld");
    ok(ixK.ledger!.historyOf(U2.publicKey[0], U2.publicKey[1]).length === 0, "…and no history items");

    // A wire-size-violating ct (unreachable from real logs today — the contract
    // length-checks — but one harness/event-shape slip away): decapsulation
    // throws inside noble, and that must become an alarm-and-withhold, NOT a
    // crashloop on the persisted cursor re-hitting the same op.
    const cNotes = [note(U2, 25n, 5005n), note(U2, 0n, 5006n)];
    ixK.applyLogs(simK.deposit("0xkemshort", cNotes[0], cNotes[1], 680000000000000000001n, 779n, {
      limbs: good.limbs,
      ciphertextHex: "0x" + "ab".repeat(10),
    }));
    const shortAlarms = ixK.ledger!.getEnvelopeAlarms();
    ok(shortAlarms.length === 2, "malformed-length ct raised a second envelope alarm (no throw)");
    const shortAlarm = shortAlarms.find((a) => a.txHash === "0xkemshort");
    ok(!!shortAlarm && /kem decapsulation failed/.test(shortAlarm.detail) && /envelope withheld/.test(shortAlarm.detail),
      "alarm names the tx + 'kem decapsulation failed … envelope withheld'");
    ok(ixK.ledger!.notesOf(U2.publicKey[0], U2.publicKey[1]).length === 0,
      "the malformed op is STOPPED — no notes recorded");

    // A V2 op reaching a ledger WITHOUT the decapsulation key is a config
    // violation the boot guard exists for — deriveOp throws, never false-alarms.
    const ixNoKey = makeIndexer(true, null);
    let msg = "";
    try {
      ixNoKey.applyLogs(makeSim().deposit("0xkemnokey", gNotes[0], gNotes[1], 640000000000000000005n, 777n, {
        limbs: good.limbs,
        ciphertextHex: good.ciphertextHex,
      }));
    } catch (e) {
      msg = (e as Error).message;
    }
    ok(/AUTHORITY_KEM_KEY/.test(msg), `keyless ledger on a V2 op throws, not alarms (got: ${msg || "no throw"})`);
  }

  step("POLL: pollOnce records failure/success state; /health projects it");
  {
    const bare = new Indexer({ rpc: DUMMY_RPC, pool: DUMMY_POOL, startBlock: 0, authorityKey: null });
    const h0 = health.handle({ ix: bare, params: [], query: new URLSearchParams() });
    ok((h0.body as { ok: boolean }).ok === false, "no mirror yet → /health ok:false");

    const pix = makeIndexer(false);
    pix.ingest = async () => {
      throw new Error("rpc down");
    };
    await pix.pollOnce();
    await pix.pollOnce();
    const h1 = health.handle({ ix: pix, params: [], query: new URLSearchParams() });
    ok((h1.body as { ok: boolean }).ok === true, "2 consecutive failures is below the persistent streak → still ok");
    await pix.pollOnce();
    ok(pix.consecutiveFailures === 3 && pix.lastError === "rpc down" && pix.lastErrorAt !== null, "pollOnce recorded the failure streak");
    const h2 = health.handle({ ix: pix, params: [], query: new URLSearchParams() });
    const b2 = h2.body as { ok: boolean; consecutiveFailures: number; lastError: string | null };
    ok(b2.ok === false && b2.consecutiveFailures === 3 && b2.lastError === "rpc down", "persistent failure streak → /health ok:false with the wedge details");

    pix.ingest = async () => {};
    await pix.pollOnce();
    ok(pix.consecutiveFailures === 0 && pix.lastSuccessAt !== null, "a successful poll clears the streak + stamps lastSuccessAt");
    const h3 = health.handle({ ix: pix, params: [], query: new URLSearchParams() });
    const b3 = h3.body as { ok: boolean; lastSuccessAt: number | null };
    ok(b3.ok === true && b3.lastSuccessAt !== null, "recovered → /health ok:true");
  }

  console.log(`\n${failures === 0 ? "INGEST UNIT TEST PASS — multicall correlation, correlation guard, replay convergence, withheld disburse, ledger dedup, pollOnce/health" : `INGEST UNIT TEST FAIL — ${failures} assertion(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nINGEST UNIT TEST ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
