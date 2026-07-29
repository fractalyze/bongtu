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
//   - transfer10, whose one op moves ten leaves through the correlation ladder
//     at once (self-merge and fan-out, plus its own replay convergence);
//   - transfer10x2, the same ten-input spend publishing only payment + change
//     (payee history == an arity-2 transfer's, self-merge pair, ABI round-trip);
//   - Disbursed with and without its DisburseCiphertexts log (withheld feed
//     entry + alarm; the ledger only opens published batches);
//   - PostgresLedger's own (txHash, logIndex) replay dedup;
//   - pollOnce failure/success state + the /health projection of it.
//
// Preconditions shared with src/chain.ts: contracts/out built (the Indexer
// constructor reads the pool ABI off the Foundry artifact). The dummy RPC below
// is never contacted.
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
import { abiKnowsKem } from "../src/chain.js";
import {
  decodeEventLog,
  encodeAbiParameters,
  encodeEventTopics,
  getAbiItem,
  parseAbi,
  toBytes,
  type Abi,
  type AbiEvent,
} from "viem";
import { disclosureChain } from "@bongtu/core/envelope";

// viem 2.55 has no encodeEventLog export, so assemble a raw {topics, data} log
// the way the chain lays one out — topic0 + indexed topics from
// encodeEventTopics, the non-indexed tail ABI-encoded into data — then decode it
// with the combined ABI to round-trip the exact fragment ingest dispatches on.
function encodeEventLog(
  item: AbiEvent,
  argsObj: Record<string, unknown>,
): { topics: [`0x${string}`, ...`0x${string}`[]]; data: `0x${string}` } {
  const indexed = item.inputs.filter((i) => i.indexed);
  const nonIndexed = item.inputs.filter((i) => !i.indexed);
  const indexedArgs = Object.fromEntries(indexed.map((i) => [i.name as string, argsObj[i.name as string]]));
  // every event here carries topic0 → a non-empty topics tuple, the shape
  // decodeEventLog wants.
  const topics = encodeEventTopics({
    abi: [item] as Abi,
    eventName: item.name,
    args: indexedArgs,
  } as Parameters<typeof encodeEventTopics>[0]) as [`0x${string}`, ...`0x${string}`[]];
  const data = encodeAbiParameters(nonIndexed, nonIndexed.map((i) => argsObj[i.name as string]) as never);
  return { topics, data };
}
// THE fixture arbiter's bjj scalar, declared once for the whole repo.
import { FIXTURE_ARBITER_SCALAR } from "../../../circuits/fixtures/fixture_lib.js";
import { health } from "../src/api/routes/health.js";
import { ViewTokenService } from "../src/api/viewtoken.js";

// Route contexts need a token service since the /auth dual-auth round; health
// never reads it — a throwaway instance satisfies the contract.
const TOKENS = new ViewTokenService(Buffer.from("ingest-test"));

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

const ARB = deriveKeypair(FIXTURE_ARBITER_SCALAR);
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

  // transfer10 has no V1 vintage (it ships with the V4 upgrade), so this builder
  // is V2-only. `ins` are the REAL inputs — all owned by ins[0].owner, which is
  // what the envelope's single input-owner head encodes — and `outs` the real
  // outputs; both are padded to arity 10 with value-0 self notes, the wallet's
  // convention. Receiver i is keyed at `nonce + i` (§11-8 v1.1 per-output
  // nonce), the thing that makes a self-merge's ten identical output owners safe.
  const transfer10 = (
    txHash: string,
    ins: NoteSpec[],
    outs: NoteSpec[],
    eph: bigint,
    nonce: bigint,
    nfs: bigint[],
    padSaltBase: bigint,
  ): ParsedLog[] => {
    tx();
    const N = 10;
    const sender = ins[0].owner;
    const pad = (n: number, base: bigint): NoteSpec[] =>
      Array.from({ length: n }, (_, i) => note(sender, 0n, base + BigInt(i)));
    const inAll = [...ins, ...pad(N - ins.length, padSaltBase)];
    const outAll = [...outs, ...pad(N - outs.length, padSaltBase + 100n)];
    const commits = outAll.map(commitOf);
    const logs = commits.map((c) => appended(txHash, c));
    const plain = [
      ...pub2(sender),
      ...inAll.flatMap((n) => [n.v, n.s]),
      ...outAll.flatMap((n) => pub2(n.owner)),
      ...outAll.flatMap((n) => [n.v, n.s]),
    ];
    logs.push(
      log("Transferred10", txHash, {
        outputCommitments: commits,
        nullifiers: nfs,
        epoch: 1n,
        ecdhPublicKey: pub2(deriveKeypair(eph)),
        encryptedValuesForReceivers: outAll.flatMap((o, i) =>
          poseidonEncrypt([o.v, o.s], ecdhSharedSecret(eph, o.owner.publicKey), nonce + BigInt(i))),
        encryptedValuesForAuthority: poseidonEncrypt(plain, ecdhSharedSecret(eph, ARB.publicKey), nonce),
        encryptionNonce: nonce,
      }),
    );
    return logs;
  };

  // transfer10x2 (V5) shares transfer10's input side — `ins` all owned by
  // ins[0].owner, padded to 10 zero-value self notes — but publishes exactly
  // TWO outputs (payment + change), each still keyed at `nonce + i`.
  const transfer10x2 = (
    txHash: string,
    ins: NoteSpec[],
    outs: [NoteSpec, NoteSpec],
    eph: bigint,
    nonce: bigint,
    nfs: bigint[],
    padSaltBase: bigint,
  ): ParsedLog[] => {
    tx();
    const sender = ins[0].owner;
    const inAll = [
      ...ins,
      ...Array.from({ length: 10 - ins.length }, (_, i) => note(sender, 0n, padSaltBase + BigInt(i))),
    ];
    const commits = outs.map(commitOf);
    const logs = commits.map((c) => appended(txHash, c));
    const plain = [
      ...pub2(sender),
      ...inAll.flatMap((n) => [n.v, n.s]),
      ...outs.flatMap((n) => pub2(n.owner)),
      ...outs.flatMap((n) => [n.v, n.s]),
    ];
    logs.push(
      log("Transferred10x2", txHash, {
        outputCommitments: commits,
        nullifiers: nfs,
        epoch: 1n,
        ecdhPublicKey: pub2(deriveKeypair(eph)),
        encryptedValuesForReceivers: outs.flatMap((o, i) =>
          poseidonEncrypt([o.v, o.s], ecdhSharedSecret(eph, o.owner.publicKey), nonce + BigInt(i))),
        encryptedValuesForAuthority: poseidonEncrypt(plain, ecdhSharedSecret(eph, ARB.publicKey), nonce),
        encryptionNonce: nonce,
      }),
    );
    return logs;
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

  return { oracle, deposit, transfer, transfer10, transfer10x2, disburse };
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
  // 2 deposits + 3 sent and NOTHING else: transfer#1's change (18 back to EMP)
  // stays suppressed.
  ok(empHist.length === 5, "employer history = 2 deposit + 3 sent — the self change is never listed");
  const u3Hist = ix.ledger!.historyOf(U3.publicKey[0], U3.publicKey[1]);
  ok(
    u3Hist.some((h) => h.kind === "received" && h.amount === "15" && h.counterparty === packPubkey(EMP.publicKey)),
    "U3 'received' 15 from the employer",
  );

  step("SELF-SEND: a pure A→A transfer yields a matched 'sent' + 'received' pair (fractalyze/bongtu#1)");
  {
    const simS = makeSim();
    const ixS = makeIndexer(true);
    const sDep0 = note(U1, 30n, 6001n);
    const sDep1 = note(U1, 0n, 6002n);
    // The wallet A→A shape (legal since the §11-8 v1.1 per-output nonce):
    // payment slot (output 0) 12 back to U1, change (output 1) 18 back to U1.
    // Without this branch the change-suppression rule would erase the op.
    const sPay = note(U1, 12n, 6003n);
    const sChg = note(U1, 18n, 6004n);
    ixS.applyLogs([
      ...simS.deposit("0xsdep", sDep0, sDep1, 690000000000000000007n, 661n),
      ...simS.transfer("0xself", sDep0, note(U1, 0n, 6005n), sPay, sChg, 691000000000000000009n, 662n, [401n, 0n]),
    ]);
    const self = packPubkey(U1.publicKey);
    const h = ixS.ledger!.historyOf(U1.publicKey[0], U1.publicKey[1]);
    const pair = h.filter((x) => x.txHash === "0xself");
    ok(pair.length === 2, "the pure self-send yields exactly two items");
    // The feed is seq-DESC and the drafts are emitted sent-then-received, so the
    // NEWER (higher-seq) 'received' sorts above the 'sent'. That order is pinned.
    ok(pair[0].kind === "received" && pair[1].kind === "sent", "the pair reads received-above-sent in the seq-desc feed");
    ok(pair.every((x) => x.amount === "12"), "both carry the payment slot (output 0), not the sum and not the change");
    ok(pair.every((x) => x.counterparty === self), "both name the sender's OWN key as counterparty");

    // The consolidation-merge shape (U-Y1's producer): both real inputs, output 0
    // = the merged sum, output 1 = 0 — the pair carries the WHOLE merged amount.
    const sMerged = note(U1, 30n, 6006n);
    ixS.applyLogs(
      simS.transfer("0xmerge", sPay, sChg, sMerged, note(U1, 0n, 6007n), 692000000000000000003n, 663n, [402n, 403n]),
    );
    const h2 = ixS.ledger!.historyOf(U1.publicKey[0], U1.publicKey[1]);
    const merged = h2.filter((x) => x.txHash === "0xmerge");
    ok(merged.length === 2, "a consolidation merge yields the same two-item pair");
    ok(merged.every((x) => x.amount === "30"), "the pair carries the merged sum");
    ok(
      merged.some((x) => x.kind === "sent") && merged.some((x) => x.kind === "received"),
      "one of each kind, both owned by the merger",
    );
    const notesS = ixS.ledger!.notesOf(U1.publicKey[0], U1.publicKey[1]);
    ok(notesS.filter((n) => !n.spent && n.value !== "0").length === 1, "after the merge exactly one live nonzero note remains");
  }

  step("TRANSFER10: a 4-input self-merge ingests as ONE op — 10 leaves, 4 spends, a self-send pair");
  {
    const sim10 = makeSim();
    const ix10 = makeIndexer(true);
    // Four notes for U1 (two deposits), then ONE transfer10 merging all four
    // into a single note — the shape the 2-in circuit needed a chain of
    // self-sends for. The other six input slots and nine output slots are pads.
    const f = [note(U1, 10n, 7001n), note(U1, 20n, 7002n), note(U1, 30n, 7003n), note(U1, 40n, 7004n)];
    const merged = note(U1, 100n, 7101n);
    const nfs = [501n, 502n, 503n, 504n, 0n, 0n, 0n, 0n, 0n, 0n];
    ix10.applyLogs([
      ...sim10.deposit("0xm1", f[0], f[1], 600000000000000000011n, 771n),
      ...sim10.deposit("0xm2", f[2], f[3], 610000000000000000013n, 772n),
      ...sim10.transfer10("0xmerge10", f, [merged], 620000000000000000017n, 773n, nfs, 7200n),
    ]);

    ok(ix10.tree.root() === sim10.oracle.getRoot(), "mirror root == reference oracle root after transfer10");
    ok(ix10.tree.nextLeafIndex() === 14, `4 deposit leaves + 10 transfer10 leaves (got ${ix10.tree.nextLeafIndex()})`);
    const feed10 = ix10.store.allEvents();
    ok(feed10.map((e) => e.kind).join(",") === "deposit,deposit,transfer10", "transfer10 joins the feed under its own kind");
    const e10 = feed10[2];
    ok(e10.slices.length === 11, "ten receiver slices + the authority tail");
    ok(e10.slices.slice(0, 10).every((s, i) => s.offset === i * 4 && s.elts === 4 && s.leafIndex === 4 + i),
      "receiver slice i sits at offset 4i and names leaf 4+i (flat uint256[40], leaf order)");
    const tail = e10.slices[10];
    ok(tail.offset === 40 && tail.elts === 64 && tail.leafIndex === null, "the authority envelope is a 64-element non-leaf tail at offset 40");
    ok(e10.ciphertext.length === 104, "feed carries all 104 ciphertext elements (40 receiver + 64 authority)");
    ok(new Set(ix10.store.nullifiers()).size === 4, "only the 4 real nullifiers are spent (the 6 padded 0s are skipped)");

    const u1n = ix10.ledger!.notesOf(U1.publicKey[0], U1.publicKey[1]);
    ok(f.every((n) => u1n.some((x) => x.commitment === commitOf(n).toString() && x.spent)),
      "all four merged inputs marked spent from the envelope alone");
    const live = u1n.filter((n) => !n.spent && n.value !== "0");
    ok(live.length === 1 && live[0].value === "100" && live[0].leafIndex === 4,
      "exactly one live note remains, the merged 100 at the first output leaf");

    // deriveHistory routes transfer10 through the SAME branch as transfer, so a
    // merge with every nonzero output back to the sender is the pure self-send
    // case: one "sent" + one "received" over the payment slot (test/deriveHistory
    // pins that table at arity 2).
    const h10 = ix10.ledger!.historyOf(U1.publicKey[0], U1.publicKey[1]).filter((x) => x.txHash === "0xmerge10");
    ok(h10.length === 2, "the self-merge yields exactly the two-item pair");
    ok(h10[0].kind === "received" && h10[1].kind === "sent", "received-above-sent in the seq-desc feed");
    ok(h10.every((x) => x.amount === "100" && x.counterparty === packPubkey(U1.publicKey)),
      "both carry the merged sum and name the merger's own key");
  }

  step("TRANSFER10: a fan-out to two payees is sent-for-payer / received-for-payee, per payee");
  {
    const simF = makeSim();
    const ixF = makeIndexer(true);
    const src = [note(EMP, 50n, 8001n), note(EMP, 50n, 8002n)];
    const payA = note(U1, 30n, 8101n);
    const payB = note(U2, 60n, 8102n);
    const chg = note(EMP, 10n, 8103n);
    ixF.applyLogs([
      ...simF.deposit("0xf1", src[0], src[1], 630000000000000000019n, 781n),
      ...simF.transfer10("0xfan10", src, [payA, payB, chg], 640000000000000000023n, 782n,
        [601n, 602n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n], 8200n),
    ]);

    const empH = ixF.ledger!.historyOf(EMP.publicKey[0], EMP.publicKey[1]).filter((x) => x.txHash === "0xfan10");
    const sentTo10 = (kp: typeof U1): string | undefined =>
      empH.find((x) => x.kind === "sent" && x.counterparty === packPubkey(kp.publicKey))?.amount;
    ok(sentTo10(U1) === "30" && sentTo10(U2) === "60", "one 'sent' per non-self payee, never merged");
    ok(empH.length === 2, "the sender's own change output stays suppressed (2 items, not 3)");
    ok(ixF.ledger!.historyOf(U1.publicKey[0], U1.publicKey[1])
      .some((x) => x.kind === "received" && x.amount === "30" && x.counterparty === packPubkey(EMP.publicKey)),
      "payee U1 'received' 30 from the sender");
    ok(ixF.ledger!.notesOf(U2.publicKey[0], U2.publicKey[1]).some((n) => n.value === "60" && !n.spent),
      "payee U2's note is recorded live at its own leaf");
  }

  step("TRANSFER10: replaying the range converges (no doubled leaves, notes or nullifiers)");
  {
    const simR = makeSim();
    const ixR = makeIndexer(true);
    const src = [note(U3, 25n, 8501n), note(U3, 25n, 8502n)];
    const logsR = [
      ...simR.deposit("0xr1", src[0], src[1], 650000000000000000029n, 791n),
      ...simR.transfer10("0xr2", src, [note(U3, 50n, 8601n)], 660000000000000000031n, 792n,
        [701n, 702n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n], 8700n),
    ];
    ixR.applyLogs(logsR);
    const before = ixR.ledger!.notesOf(U3.publicKey[0], U3.publicKey[1]).length;
    ixR.applyLogs(logsR);
    ok(ixR.store.allEvents().length === 2, "feed did not grow on replay");
    ok(ixR.tree.nextLeafIndex() === 12 && ixR.tree.root() === simR.oracle.getRoot(), "tree unchanged on replay");
    ok(ixR.ledger!.notesOf(U3.publicKey[0], U3.publicKey[1]).length === before, "ledger notes did not double on replay");
    ok(new Set(ixR.store.nullifiers()).size === 2, "nullifier set unchanged on replay");
  }

  step("TRANSFER10X2: 4 real inputs + payee + change ingests as ONE op with transfer-identical rows");
  {
    const simX = makeSim();
    const ixX = makeIndexer(true);
    // Four notes for U1 across two deposits, all four spent through ONE
    // transfer10x2: pay U2 70, change 30 back to U1. The history must read
    // exactly like an arity-2 transfer's — one 'received' for the payee, one
    // 'sent' for the payer, the self change suppressed.
    const f = [note(U1, 10n, 9001n), note(U1, 20n, 9002n), note(U1, 30n, 9003n), note(U1, 40n, 9004n)];
    const pay = note(U2, 70n, 9101n);
    const chg = note(U1, 30n, 9102n);
    const nfs = [801n, 802n, 803n, 804n, 0n, 0n, 0n, 0n, 0n, 0n];
    const logsX = [
      ...simX.deposit("0xx1", f[0], f[1], 670000000000000000037n, 811n),
      ...simX.deposit("0xx2", f[2], f[3], 680000000000000000041n, 812n),
      ...simX.transfer10x2("0xpay10x2", f, [pay, chg], 690000000000000000043n, 813n, nfs, 9200n),
    ];
    ixX.applyLogs(logsX);

    ok(ixX.tree.root() === simX.oracle.getRoot(), "mirror root == reference oracle root after transfer10x2");
    ok(ixX.tree.nextLeafIndex() === 6, `4 deposit leaves + 2 transfer10x2 leaves (got ${ixX.tree.nextLeafIndex()})`);
    const feedX = ixX.store.allEvents();
    ok(feedX.map((e) => e.kind).join(",") === "deposit,deposit,transfer10x2", "transfer10x2 joins the feed under its own kind");
    const eX = feedX[2];
    ok(eX.slices.length === 3, "two receiver slices + the authority tail");
    ok(eX.slices[0].offset === 0 && eX.slices[0].elts === 4 && eX.slices[0].leafIndex === 4
      && eX.slices[1].offset === 4 && eX.slices[1].elts === 4 && eX.slices[1].leafIndex === 5,
      "receiver slice i sits at offset 4i and names leaf 4+i (flat uint256[8], leaf order)");
    const tailX = eX.slices[2];
    ok(tailX.offset === 8 && tailX.elts === 31 && tailX.leafIndex === null, "the authority envelope is a 31-element non-leaf tail at offset 8");
    ok(eX.ciphertext.length === 39, "feed carries all 39 ciphertext elements (8 receiver + 31 authority)");
    ok(new Set(ixX.store.nullifiers()).size === 4, "only the 4 real nullifiers are spent (the 6 padded 0s are skipped)");

    const u1x = ixX.ledger!.notesOf(U1.publicKey[0], U1.publicKey[1]);
    ok(f.every((n) => u1x.some((x) => x.commitment === commitOf(n).toString() && x.spent)),
      "all four spent inputs marked spent from the envelope alone");
    const u1live = u1x.filter((n) => !n.spent && n.value !== "0");
    ok(u1live.length === 1 && u1live[0].value === "30" && u1live[0].leafIndex === 5,
      "the payer keeps exactly the change note at the second output leaf");
    const u2x = ixX.ledger!.notesOf(U2.publicKey[0], U2.publicKey[1]);
    ok(u2x.length === 1 && u2x[0].value === "70" && u2x[0].leafIndex === 4 && !u2x[0].spent,
      "the payee's note is recorded live at the first output leaf");

    const payH = ixX.ledger!.historyOf(U2.publicKey[0], U2.publicKey[1]).filter((x) => x.txHash === "0xpay10x2");
    ok(payH.length === 1 && payH[0].kind === "received" && payH[0].amount === "70"
      && payH[0].counterparty === packPubkey(U1.publicKey),
      "payee history: one 'received 70 from the payer' — exactly a transfer's row");
    const senderH = ixX.ledger!.historyOf(U1.publicKey[0], U1.publicKey[1]).filter((x) => x.txHash === "0xpay10x2");
    ok(senderH.length === 1 && senderH[0].kind === "sent" && senderH[0].amount === "70"
      && senderH[0].counterparty === packPubkey(U2.publicKey),
      "payer history: one 'sent 70 to the payee' — the self change stays suppressed");

    // Replay convergence rides along: the same range twice must not double
    // anything (the poll loop retries from an unadvanced cursor after a throw).
    ixX.applyLogs(logsX);
    ok(ixX.store.allEvents().length === 3, "feed did not grow on replay");
    ok(ixX.tree.nextLeafIndex() === 6 && ixX.tree.root() === simX.oracle.getRoot(), "tree unchanged on replay");
    ok(ixX.ledger!.notesOf(U1.publicKey[0], U1.publicKey[1]).length === u1x.length, "ledger notes did not double on replay");
    ok(new Set(ixX.store.nullifiers()).size === 4, "nullifier set unchanged on replay");
  }

  step("TRANSFER10X2: a merge with both outputs self surfaces as the self-send pair");
  {
    const simM = makeSim();
    const ixM = makeIndexer(true);
    const src = [note(U3, 60n, 9501n), note(U3, 40n, 9502n)];
    const merged = note(U3, 100n, 9601n);
    ixM.applyLogs([
      ...simM.deposit("0xm10x2", src[0], src[1], 700000000000000000047n, 821n),
      ...simM.transfer10x2("0xmerge10x2", src, [merged, note(U3, 0n, 9602n)], 710000000000000000051n, 822n,
        [901n, 902n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n], 9700n),
    ]);
    const hM = ixM.ledger!.historyOf(U3.publicKey[0], U3.publicKey[1]).filter((x) => x.txHash === "0xmerge10x2");
    ok(hM.length === 2, "the self-merge yields exactly the two-item pair");
    ok(hM[0].kind === "received" && hM[1].kind === "sent", "received-above-sent in the seq-desc feed");
    ok(hM.every((x) => x.amount === "100" && x.counterparty === packPubkey(U3.publicKey)),
      "both carry the merged sum and name the merger's own key");
    const liveM = ixM.ledger!.notesOf(U3.publicKey[0], U3.publicKey[1]).filter((n) => !n.spent && n.value !== "0");
    ok(liveM.length === 1 && liveM[0].value === "100", "after the merge exactly one live nonzero note remains");
  }

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

  step("DUAL ABI: the combined ABI decodes BOTH V1 and V2 raw event encodings");
  {
    // Encode a raw log under each vintage's own single-fragment ABI, then decode
    // with the indexer's combined ABI (what getLogsChunked dispatches on):
    // topic0 differs between vintages, so a V2-only ABI would drop V1 history on
    // the floor — the silent-skip failure the dual ABI closes.
    const abi = ix.abi;
    ok(abiKnowsKem(abi), "combined ABI models the V2 (kemCiphertext) events");
    const v1Dep = parseAbi([
      "event Deposited(uint256 indexed epoch, uint256 firstLeafIndex, uint256 oc0, uint256 oc1, uint256 amount, uint256[2] ecdhPublicKey, uint256[10] encryptedValuesForAuthority, uint256 encryptionNonce, uint256 root)",
    ])[0] as AbiEvent;
    const depArgs: Record<string, unknown> = {
      epoch: 1n, firstLeafIndex: 0n, oc0: 11n, oc1: 12n, amount: 5n,
      ecdhPublicKey: [1n, 2n], encryptedValuesForAuthority: new Array(10).fill(3n),
      encryptionNonce: 42n, root: 99n,
    };
    const v1Raw = encodeEventLog(v1Dep, depArgs);
    // decodeEventLog dispatches on topic0 (no eventName passed) — the exact
    // getLogsChunked path. args come back keyed by input NAME.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const v1Parsed = decodeEventLog({ abi, data: v1Raw.data, topics: v1Raw.topics }) as { eventName: string; args: any };
    ok(v1Parsed.eventName === "Deposited" && v1Parsed.args.kemBinding === undefined,
      "a V1-encoded Deposited decodes under the combined ABI, WITHOUT kem fields (-> kem: null)");
    // the V2 fragment = the built Deposited that carries kemCiphertext
    const v2Frag = abi.find(
      (e): e is AbiEvent => e.type === "event" && e.name === "Deposited" && e.inputs.some((i) => i.name === "kemCiphertext"),
    )!;
    const v2Raw = encodeEventLog(v2Frag, { ...depArgs, kemBinding: 77n, kemCiphertext: "0x" + "ab".repeat(1088) });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const v2Parsed = decodeEventLog({ abi, data: v2Raw.data, topics: v2Raw.topics }) as { eventName: string; args: any };
    ok(v2Parsed.eventName === "Deposited" && v2Parsed.args.kemBinding !== undefined
      && toBytes(v2Parsed.args.kemCiphertext).length === 1088,
      "a V2-encoded Deposited decodes with kemBinding + a 1088-byte kemCiphertext");
    ok(v1Raw.topics[0] !== v2Raw.topics[0], "V1/V2 topic0 differ (the reason dual-ABI is required)");
  }

  step("TRANSFER10 ABI: the pool's own event fragment decodes into the names ingest destructures");
  {
    // The scenarios above drive applyLogs with SYNTHETIC ParsedLogs, so nothing
    // there would catch an ingest branch reading a field the emitted event does
    // not actually carry (or carries at another width). Round-trip a
    // Transferred10 through the real built ABI and check exactly the fields the
    // branch touches. transfer10 has no V1 vintage, so there is only one shape.
    const abi = ix.abi;
    const item = getAbiItem({ abi, name: "Transferred10" }) as AbiEvent;
    const raw = encodeEventLog(item, {
      epoch: 1n,
      nullifiers: Array.from({ length: 10 }, (_, i) => BigInt(100 + i)),
      outputCommitments: Array.from({ length: 10 }, (_, i) => BigInt(200 + i)),
      ecdhPublicKey: [1n, 2n],
      encryptedValuesForReceivers: new Array(40).fill(3n),
      encryptedValuesForAuthority: new Array(64).fill(4n),
      encryptionNonce: 42n,
      root: 99n,
      kemBinding: 77n,
      kemCiphertext: "0x" + "ab".repeat(1088),
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = decodeEventLog({ abi, data: raw.data, topics: raw.topics }) as { eventName: string; args: any };
    ok(p.eventName === "Transferred10", "the built ABI models Transferred10");
    ok(p.args.nullifiers.length === 10 && p.args.outputCommitments.length === 10,
      "ten nullifiers and ten output commitments");
    ok(p.args.encryptedValuesForReceivers.length === 40, "receiver ciphertexts arrive as ONE flat 40-element run");
    ok(p.args.encryptedValuesForAuthority.length === 64, "the authority envelope is 64 elements at arity 10");
    ok(p.args.kemBinding !== undefined && toBytes(p.args.kemCiphertext).length === 1088,
      "kemBinding + a 1088-byte kemCiphertext ride along (kemOf dispatches on their presence)");
    ok(Number(p.args.epoch) === 1 && Number(p.args.encryptionNonce) === 42,
      "epoch and encryptionNonce decode where the feed entry reads them");
  }

  step("TRANSFER10X2 ABI: the pool's own event fragment decodes into the names ingest destructures");
  {
    // Same silent-skip risk as Transferred10: the synthetic scenarios cannot
    // catch the branch reading a field the emitted V5 event does not carry (or
    // at another width), so round-trip through the real built ABI. One shape
    // only — the entry point ships with the V5 upgrade.
    const abi = ix.abi;
    const item = getAbiItem({ abi, name: "Transferred10x2" }) as AbiEvent;
    const raw = encodeEventLog(item, {
      epoch: 1n,
      nullifiers: Array.from({ length: 10 }, (_, i) => BigInt(100 + i)),
      outputCommitments: [201n, 202n],
      ecdhPublicKey: [1n, 2n],
      encryptedValuesForReceivers: new Array(8).fill(3n),
      encryptedValuesForAuthority: new Array(31).fill(4n),
      encryptionNonce: 42n,
      root: 99n,
      kemBinding: 77n,
      kemCiphertext: "0x" + "ab".repeat(1088),
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const p = decodeEventLog({ abi, data: raw.data, topics: raw.topics }) as { eventName: string; args: any };
    ok(p.eventName === "Transferred10x2", "the built ABI models Transferred10x2");
    ok(p.args.nullifiers.length === 10 && p.args.outputCommitments.length === 2,
      "ten nullifiers but only TWO output commitments");
    ok(p.args.encryptedValuesForReceivers.length === 8, "receiver ciphertexts arrive as ONE flat 8-element run");
    ok(p.args.encryptedValuesForAuthority.length === 31, "the authority envelope is 31 elements at 10-in/2-out");
    ok(p.args.kemBinding !== undefined && toBytes(p.args.kemCiphertext).length === 1088,
      "kemBinding + a 1088-byte kemCiphertext ride along (kemOf dispatches on their presence)");
    ok(Number(p.args.epoch) === 1 && Number(p.args.encryptionNonce) === 42,
      "epoch and encryptionNonce decode where the feed entry reads them");
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
    const h0 = health.handle({ ix: bare, tokens: TOKENS, params: [], query: new URLSearchParams() });
    ok((h0.body as { ok: boolean }).ok === false, "no mirror yet → /health ok:false");

    const pix = makeIndexer(false);
    pix.ingest = async () => {
      throw new Error("rpc down");
    };
    await pix.pollOnce();
    await pix.pollOnce();
    const h1 = health.handle({ ix: pix, tokens: TOKENS, params: [], query: new URLSearchParams() });
    ok((h1.body as { ok: boolean }).ok === true, "2 consecutive failures is below the persistent streak → still ok");
    await pix.pollOnce();
    ok(pix.consecutiveFailures === 3 && pix.lastError === "rpc down" && pix.lastErrorAt !== null, "pollOnce recorded the failure streak");
    const h2 = health.handle({ ix: pix, tokens: TOKENS, params: [], query: new URLSearchParams() });
    const b2 = h2.body as { ok: boolean; consecutiveFailures: number; lastError: string | null };
    ok(b2.ok === false && b2.consecutiveFailures === 3 && b2.lastError === "rpc down", "persistent failure streak → /health ok:false with the wedge details");

    pix.ingest = async () => {};
    await pix.pollOnce();
    ok(pix.consecutiveFailures === 0 && pix.lastSuccessAt !== null, "a successful poll clears the streak + stamps lastSuccessAt");
    const h3 = health.handle({ ix: pix, tokens: TOKENS, params: [], query: new URLSearchParams() });
    const b3 = h3.body as { ok: boolean; lastSuccessAt: number | null };
    ok(b3.ok === true && b3.lastSuccessAt !== null, "recovered → /health ok:true");
  }

  console.log(`\n${failures === 0 ? "INGEST UNIT TEST PASS — multicall correlation, self-send history, transfer10 merge/fan-out, transfer10x2 pay/merge, correlation guard, replay convergence, withheld disburse, ledger dedup, pollOnce/health" : `INGEST UNIT TEST FAIL — ${failures} assertion(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nINGEST UNIT TEST ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
