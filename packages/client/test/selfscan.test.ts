// Headless gates for the consumer self-scan discovery engine (selfscan.ts,
// OPMOD §3.6) — recorded mock feeds, PRNG-free (every key/seal is index- or
// seed-derived; ML-KEM encapsulations take fixed encapSeeds). Coverage:
//
//   (1) the scan finds exactly the wallet's notes, and the viewTag prefilter is
//       EFFECTIVE: a slice whose published tag misses is never decapsulated
//       (stats.decapsulations === stats.tagMatches === own-slice count);
//   (2) batch discovery: leafIndex = batchId + outputIndex, leaf-matched inline
//       against the published commitment run;
//   (3) wrong-key / junk-KEM decrypts are rejected by the leaf-match (path fold
//       or commitment-run equality) — dropped, never thrown;
//   (4) spent transitions: /nullifiers flips the flag on a later scan;
//   (5) cursor resume: scan(A..B) then scan(B..C) == scan(A..C);
//   (6) a kem-pending batch surfaces as PENDING, not silently empty, and
//       resolves into notes once the transport completes;
//   (7) enterprise coexistence: spend-key envelope notes in the same feed are
//       discovered beside consumer notes;
//   (8) the REAL consumer fixture (contracts/test/fixtures/
//       consumer_realproofs.json): the engine opens circuit-derived artifacts
//       with the shared fixture identities (circuits/fixtures/consumer_lib);
//   (9) activity/snapshot derivation and the persistence codec.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { deriveKeypair, commitment, nullifier, ecdhSharedSecret, poseidonEncrypt } from "@bongtu/core/note";
import { sealConsumerOutput } from "@bongtu/core/consumer";
import { ImtTree } from "@bongtu/core/imt";
import { ml_kem768 } from "@bongtu/core/kem";
import { packPubkey } from "@bongtu/core/pubkey";

import { deriveIdentityFromSignature, type ConsumerWalletIdentity } from "@bongtu/client/derive";
import { sumUnspent } from "@bongtu/client/balance";
import type { FeedEvent, PathResult } from "@bongtu/client/indexerClient";
import {
  scanEventsPass,
  pathConfirmsLeaf,
  runSelfScan,
  deriveScanActivity,
  selfScanSnapshot,
  encodeScanState,
  decodeScanState,
  isConsumerIdentity,
  EMPTY_SCAN_STATE,
  type SelfScanIo,
  type SelfScanState,
} from "@bongtu/client/selfscan";
import { consumerReceiver } from "../../../circuits/fixtures/consumer_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, "..", "..", "..", "contracts", "test", "fixtures", "consumer_realproofs.json");

// ---- deterministic material -------------------------------------------------

const SIG = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const ME = deriveIdentityFromSignature(SIG);
const STRANGER = deriveIdentityFromSignature("0x" + "c3".repeat(32) + "d4".repeat(32) + "1b");

const EPH = 313131313131313131313131n; // ephemeral bjj scalar of every mock op
const EPH_PUB = deriveKeypair(EPH).publicKey;
const NONCE = 987654321n;

const dec = (x: bigint): string => x.toString();
const hex = (b: Uint8Array): string => "0x" + Buffer.from(b).toString("hex");
const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);

/** Seal one output to an identity's consumer view keys at output position i. */
function sealTo(
  id: ConsumerWalletIdentity,
  value: bigint,
  salt: bigint,
  index: number,
  encapByte: number,
  nonce: bigint = NONCE,
): ReturnType<typeof sealConsumerOutput> {
  return sealConsumerOutput({
    value,
    salt,
    ephemeralPriv: EPH,
    viewPub: id.viewKeypair.publicKey,
    kemEk: id.kemKeypair.ek,
    encryptionNonce: nonce,
    index,
    encapSeed: seed(encapByte),
  });
}

/** A transferPriv-shaped feed entry: two 4-elt receiver slices, viewTags +
 *  per-output kem cts, leaf indices supplied by the caller. */
function transferPrivEvent(args: {
  seq: number;
  txHash: string;
  leaves: [number, number];
  seals: [ReturnType<typeof sealConsumerOutput>, ReturnType<typeof sealConsumerOutput>];
  nonce?: bigint;
}): FeedEvent {
  const [s0, s1] = args.seals;
  return {
    seq: args.seq,
    txHash: args.txHash,
    blockNumber: 1 + args.seq,
    kind: "transferPriv",
    epoch: null,
    ecdhPublicKey: [dec(EPH_PUB[0]), dec(EPH_PUB[1])],
    encryptionNonce: dec(args.nonce ?? NONCE),
    slices: [
      { offset: 0, elts: 4, leafIndex: args.leaves[0] },
      { offset: 4, elts: 4, leafIndex: args.leaves[1] },
    ],
    ciphertext: [...s0.cipherText, ...s1.cipherText].map(dec),
    viewTags: [dec(s0.viewTag), dec(s1.viewTag)],
    kemCiphertexts: [hex(s0.kemCiphertext), hex(s1.kemCiphertext)],
  };
}

/** IO over a recorded feed + an ImtTree oracle (paths + head), counting calls. */
function mockIo(
  feed: FeedEvent[],
  tree: ImtTree,
  nullifiers: string[] = [],
): SelfScanIo & { calls: { path: number } } {
  const calls = { path: 0 };
  return {
    calls,
    events: async (cursor, limit) => feed.filter((e) => e.seq > cursor).slice(0, limit ?? feed.length),
    nullifiers: async () => nullifiers,
    head: async () => ({ root: dec(tree.getRoot()), nextLeafIndex: tree.getNextLeafIndex() }),
    path: async (leafIndex): Promise<PathResult> => {
      calls.path += 1;
      const p = tree.merklePath(leafIndex);
      return {
        leafIndex,
        siblings: p.siblings.map(dec),
        pathIndices: p.pathIndices,
        root: dec(tree.getRoot()),
      };
    },
  };
}

// ---- (1) own notes only + prefilter effectiveness ---------------------------

test("scan finds exactly the wallet's notes; a tag-missing slice is never decapsulated", async () => {
  const mySeal = sealTo(ME, 600n, 5001n, 0, 3);
  const theirSeal = sealTo(STRANGER, 400n, 5002n, 1, 4);
  // The prefilter's discriminator: the two identities' tags differ for this
  // ephemeral key (a 1/256 coincidence would need new fixed material).
  assert.notEqual(mySeal.viewTag, theirSeal.viewTag);

  const myLeaf = commitment(600n, 5001n, ME.keypair.publicKey);
  const theirLeaf = commitment(400n, 5002n, STRANGER.keypair.publicKey);
  const tree = new ImtTree(8, 4);
  tree.appendLeaf(myLeaf);
  tree.appendLeaf(theirLeaf);

  const ev = transferPrivEvent({ seq: 0, txHash: "0xaaa", leaves: [0, 1], seals: [mySeal, theirSeal] });

  const pass = scanEventsPass([ev], ME);
  assert.equal(pass.stats.consumerSlices, 2);
  assert.equal(pass.stats.tagMatches, 1, "only the wallet's own slice passes the prefilter");
  assert.equal(pass.stats.decapsulations, pass.stats.tagMatches, "a tag miss never reaches Decaps");
  assert.equal(pass.candidates.length, 1);

  const io = mockIo([ev], tree);
  const state = await runSelfScan(io, ME);
  assert.equal(state.notes.length, 1, "exactly the wallet's note is discovered");
  const note = state.notes[0];
  assert.equal(note.value, "600");
  assert.equal(note.leafIndex, 0);
  assert.equal(note.commitment, dec(myLeaf));
  assert.equal(note.nullifier, dec(nullifier(600n, 5001n, ME.keypair.formattedPrivateKey)));
  assert.equal(note.spent, false);
  assert.equal(note.family, "consumer");
  assert.equal(sumUnspent(state.notes), 600n);
  assert.equal(state.cursor, 0);
  assert.equal(state.scannedNextLeafIndex, 2);
});

// ---- (2) + (6) batch discovery, kem transport states ------------------------

const BATCH_B = 4;
const BATCH_START = 16;

/** A disbursePriv batch: ME owns output 1, strangers the rest. */
function batchMaterial(): {
  seals: ReturnType<typeof sealConsumerOutput>[];
  commitments: bigint[];
  event: (kem: FeedEvent["kem"]) => FeedEvent;
} {
  const plans = [
    { value: 10n, salt: 8001n, id: STRANGER },
    { value: 25n, salt: 8002n, id: ME },
    { value: 30n, salt: 8003n, id: STRANGER },
    { value: 40n, salt: 8004n, id: STRANGER },
  ];
  const seals = plans.map((p, i) => sealTo(p.id, p.value, p.salt, i, 10 + i));
  const commitments = plans.map((p) => commitment(p.value, p.salt, p.id.keypair.publicKey));
  const event = (kem: FeedEvent["kem"]): FeedEvent => ({
    seq: 7,
    txHash: "0xbatch",
    blockNumber: 9,
    kind: "disbursePriv",
    epoch: null,
    ecdhPublicKey: [dec(EPH_PUB[0]), dec(EPH_PUB[1])],
    encryptionNonce: dec(NONCE),
    slices: Array.from({ length: BATCH_B }, (_, i) => ({ offset: i * 4, elts: 4, leafIndex: BATCH_START + i })),
    ciphertext: seals.flatMap((s) => s.cipherText.map(dec)),
    disclosure: "verified",
    viewTags: seals.map((s) => dec(s.viewTag)),
    batchId: BATCH_START,
    outputCommitments: commitments.map(dec),
    kem,
  });
  return { seals, commitments, event };
}

test("kem-pending batch surfaces as PENDING (not silently empty), then resolves into a leaf-mapped note", async () => {
  const { seals, event } = batchMaterial();
  const tree = new ImtTree(8, 4);
  const pendingEv = event({ status: "pending", chunkCount: 3, acceptedCount: 1 });

  const first = await runSelfScan(mockIo([pendingEv], tree), ME);
  assert.equal(first.notes.length, 0);
  assert.deepEqual(first.pending, [{ seq: 7, txHash: "0xbatch", batchId: BATCH_START, status: "pending" }]);
  assert.equal(first.cursor, 7, "the cursor advances past a pending batch (its seq is re-read, not re-windowed)");

  // Transport completes: the SAME seq now carries assembled per-output kem cts.
  const completeEv = event({
    status: "complete",
    chunkCount: 3,
    acceptedCount: 3,
    kemCiphertexts: seals.map((s) => hex(s.kemCiphertext)),
  });
  const second = await runSelfScan(mockIo([completeEv], tree), ME, first);
  assert.equal(second.pending.length, 0, "a resolved batch leaves the pending set");
  assert.equal(second.notes.length, 1);
  assert.equal(second.notes[0].value, "25");
  assert.equal(second.notes[0].leafIndex, BATCH_START + 1, "leafIndex = batchId + outputIndex");
  assert.equal(second.notes[0].kind, "disbursePriv");
});

test("a disclosure-incomplete batch (production shape: fields ABSENT) is pending, then resolves; a foreign batch is skipped", async () => {
  const { seals, event } = batchMaterial();
  // The real indexer serves an incomplete run with viewTags/outputCommitments
  // ABSENT and no slices (ingest adds the consumer fields only when the §4.1
  // run is full) — NOT as empty arrays. Without the scan's pre-gate this shape
  // matches neither branch and the batch would be silently skipped forever.
  const { viewTags: _vt, outputCommitments: _oc, kem: _kem, ...rest } = event(undefined);
  const bare: FeedEvent = { ...rest, slices: [], ciphertext: [] };
  const pass = scanEventsPass([bare], ME);
  assert.deepEqual(pass.pending, [{ seq: 7, txHash: "0xbatch", batchId: BATCH_START, status: "disclosure-incomplete" }]);

  // Through the shell: surfaced as pending (never silently empty), retained...
  const tree = new ImtTree(8, 4);
  const first = await runSelfScan(mockIo([bare], tree), ME);
  assert.equal(first.notes.length, 0);
  assert.deepEqual(first.pending, [{ seq: 7, txHash: "0xbatch", batchId: BATCH_START, status: "disclosure-incomplete" }]);

  // ...and resolved into its note once a later feed page carries the full run.
  const completeEv = event({
    status: "complete",
    chunkCount: 3,
    acceptedCount: 3,
    kemCiphertexts: seals.map((s) => hex(s.kemCiphertext)),
  });
  const second = await runSelfScan(mockIo([completeEv], tree), ME, first);
  assert.equal(second.pending.length, 0, "the resolved batch leaves the pending set");
  assert.equal(second.notes.length, 1);
  assert.equal(second.notes[0].value, "25");

  // Full disclosure, kem pending, but NO slice tags this wallet: not ours (up
  // to 2^-8), so it must not linger in the pending set forever.
  const foreign = batchMaterial();
  const foreignEv = {
    ...foreign.event({ status: "pending", chunkCount: 3, acceptedCount: 0 }),
    viewTags: ["1", "2", "3", "4"].map((t) => dec((BigInt(t) + 1n + consumerTagOf(ME)) % 256n)),
  };
  const pass2 = scanEventsPass([foreignEv], ME);
  assert.equal(pass2.pending.length, 0);
  assert.equal(pass2.stats.decapsulations, 0);
});

/** The wallet's own tag under the shared mock ephemeral key. */
function consumerTagOf(id: ConsumerWalletIdentity): bigint {
  const seals = sealTo(id, 1n, 1n, 0, 99);
  return seals.viewTag;
}

// ---- (3) wrong-key / garbage rejection --------------------------------------

test("junk KEM ct and forged-tag decrypts are rejected by the leaf-match, never thrown", async () => {
  const mySeal = sealTo(ME, 600n, 5001n, 0, 3);
  const myLeaf = commitment(600n, 5001n, ME.keypair.publicKey);
  const tree = new ImtTree(8, 4);
  tree.appendLeaf(myLeaf);
  tree.appendLeaf(commitment(1n, 1n, STRANGER.keypair.publicKey));

  // (a) tampered kem ct: implicit rejection decrypts garbage; the path fold
  // cannot reproduce the root, so the candidate is dropped.
  const tampered = Uint8Array.from(mySeal.kemCiphertext);
  tampered[0] ^= 0xff;
  const evTampered = transferPrivEvent({
    seq: 0,
    txHash: "0xbad",
    leaves: [0, 1],
    seals: [{ ...mySeal, kemCiphertext: tampered }, sealTo(STRANGER, 1n, 1n, 1, 4)],
  });
  const s1 = await runSelfScan(mockIo([evTampered], tree), ME);
  assert.equal(s1.notes.length, 0, "junk-KEM decrypt fails the leaf-match");

  // (b) forged tag: a stranger's ct whose published tag is faked to ours still
  // decrypts to garbage — dropped by the same rule (the §3.2 silent-
  // undiscoverability class ends at the leaf-match, never in a throw).
  const theirSeal = sealTo(STRANGER, 400n, 5002n, 0, 5);
  const forged: FeedEvent = {
    ...transferPrivEvent({ seq: 0, txHash: "0xforged", leaves: [0, 1], seals: [theirSeal, theirSeal] }),
    viewTags: [dec(mySeal.viewTag), dec(mySeal.viewTag)],
  };
  const s2 = await runSelfScan(mockIo([forged], tree), ME);
  assert.equal(s2.notes.length, 0, "forged-tag decrypt fails the leaf-match");

  // (c) batch leaf mismatch: commitment run disagrees with the decrypt.
  const { seals, event } = batchMaterial();
  const wrongRun = {
    ...event({ status: "complete", chunkCount: 1, acceptedCount: 1, kemCiphertexts: seals.map((s) => hex(s.kemCiphertext)) }),
    outputCommitments: ["1", "2", "3", "4"],
  };
  const pass = scanEventsPass([wrongRun], ME);
  assert.equal(pass.accepted.length, 0, "a run mismatch drops the batch note");
});

test("pathConfirmsLeaf: the real leaf folds to the root; any other value does not", () => {
  const tree = new ImtTree(8, 4);
  const leaf = commitment(600n, 5001n, ME.keypair.publicKey);
  tree.appendLeaf(leaf);
  const p = tree.merklePath(0);
  const path = { siblings: p.siblings.map(dec), root: dec(tree.getRoot()) };
  assert.equal(pathConfirmsLeaf(dec(leaf), path, 0), true);
  assert.equal(pathConfirmsLeaf(dec(leaf + 1n), path, 0), false);
});

// ---- (4) spent transitions --------------------------------------------------

test("a nullifier landing in /nullifiers flips the note to spent on the next scan", async () => {
  const mySeal = sealTo(ME, 600n, 5001n, 0, 3);
  const myLeaf = commitment(600n, 5001n, ME.keypair.publicKey);
  const nf = nullifier(600n, 5001n, ME.keypair.formattedPrivateKey);
  const tree = new ImtTree(8, 4);
  tree.appendLeaf(myLeaf);
  tree.appendLeaf(commitment(1n, 1n, STRANGER.keypair.publicKey));
  const ev = transferPrivEvent({ seq: 0, txHash: "0xaaa", leaves: [0, 1], seals: [mySeal, sealTo(STRANGER, 1n, 1n, 1, 4)] });

  const s1 = await runSelfScan(mockIo([ev], tree), ME);
  assert.equal(s1.notes[0].spent, false);
  assert.equal(sumUnspent(s1.notes), 600n);

  const s2 = await runSelfScan(mockIo([ev], tree, [dec(nf)]), ME, s1);
  assert.equal(s2.notes.length, 1, "the spent note is kept (flag flip, not removal)");
  assert.equal(s2.notes[0].spent, true);
  assert.equal(sumUnspent(s2.notes), 0n);
});

// ---- (5) cursor resume ------------------------------------------------------

test("cursor resume: scan(A..B) then scan(B..C) equals scan(A..C)", async () => {
  const sealA = sealTo(ME, 100n, 6001n, 0, 20);
  const sealB = sealTo(ME, 200n, 6002n, 0, 21);
  const leafA = commitment(100n, 6001n, ME.keypair.publicKey);
  const leafB = commitment(200n, 6002n, ME.keypair.publicKey);
  const tree = new ImtTree(8, 4);
  tree.appendLeaf(leafA);
  tree.appendLeaf(commitment(1n, 1n, STRANGER.keypair.publicKey));
  tree.appendLeaf(leafB);
  tree.appendLeaf(commitment(2n, 2n, STRANGER.keypair.publicKey));

  const evA = transferPrivEvent({ seq: 0, txHash: "0xa", leaves: [0, 1], seals: [sealA, sealTo(STRANGER, 1n, 1n, 1, 22)] });
  const evB = transferPrivEvent({ seq: 1, txHash: "0xb", leaves: [2, 3], seals: [sealB, sealTo(STRANGER, 2n, 2n, 1, 23)] });

  const whole = await runSelfScan(mockIo([evA, evB], tree), ME);
  const firstHalf = await runSelfScan(mockIo([evA], tree), ME);
  const resumed = await runSelfScan(mockIo([evA, evB], tree), ME, firstHalf);
  assert.deepEqual(resumed, whole, "the staged scan lands on the identical state");
  assert.equal(whole.notes.length, 2);
  assert.equal(whole.cursor, 1);

  // And the resumed leg did not re-read the already-scanned window.
  const countingIo = mockIo([evA, evB], tree);
  const again = await runSelfScan(countingIo, ME, firstHalf);
  assert.equal(again.notes.length, 2);
  assert.equal(countingIo.calls.path, 1, "only the NEW window's candidate hits /path");
});

test("initial sync drains the feed: paged reads equal one big page; a capped run stamps only what it scanned", async () => {
  const sealA = sealTo(ME, 100n, 6001n, 0, 30);
  const sealB = sealTo(ME, 200n, 6002n, 0, 31);
  const sealC = sealTo(ME, 300n, 6003n, 0, 32);
  const tree = new ImtTree(8, 4);
  tree.appendLeaf(commitment(100n, 6001n, ME.keypair.publicKey));
  tree.appendLeaf(commitment(1n, 1n, STRANGER.keypair.publicKey));
  tree.appendLeaf(commitment(200n, 6002n, ME.keypair.publicKey));
  tree.appendLeaf(commitment(2n, 2n, STRANGER.keypair.publicKey));
  tree.appendLeaf(commitment(300n, 6003n, ME.keypair.publicKey));
  tree.appendLeaf(commitment(3n, 3n, STRANGER.keypair.publicKey));
  const feed = [
    transferPrivEvent({ seq: 0, txHash: "0xa", leaves: [0, 1], seals: [sealA, sealTo(STRANGER, 1n, 1n, 1, 33)] }),
    transferPrivEvent({ seq: 1, txHash: "0xb", leaves: [2, 3], seals: [sealB, sealTo(STRANGER, 2n, 2n, 1, 34)] }),
    transferPrivEvent({ seq: 2, txHash: "0xc", leaves: [4, 5], seals: [sealC, sealTo(STRANGER, 3n, 3n, 1, 35)] }),
  ];
  // A paged io serving ONE event per /events read — the initial-sync shape
  // where /head is far past the first page.
  const paged = (): SelfScanIo => ({
    ...mockIo(feed, tree),
    events: async (cursor) => feed.filter((e) => e.seq > cursor).slice(0, 1),
  });

  const whole = await runSelfScan(mockIo(feed, tree), ME);
  assert.equal(whole.notes.length, 3);
  assert.equal(whole.scannedNextLeafIndex, 6);
  const drainedState = await runSelfScan(paged(), ME);
  assert.deepEqual(drainedState, whole, "one scan drains every page before stamping");

  // Capped mid-feed: the stamp is the coverage actually scanned — NEVER the
  // head — so the sync dot reads stale and a later scan finishes the sync.
  const capped = await runSelfScan(paged(), ME, EMPTY_SCAN_STATE, { maxPages: 1 });
  assert.equal(capped.notes.length, 1, "one page scanned under the cap");
  assert.equal(capped.scannedNextLeafIndex, 2, "stamped to the scanned window's coverage, not /head's 6");
  const resumed = await runSelfScan(paged(), ME, capped);
  assert.deepEqual(resumed, whole, "the capped run resumes into the identical state");
});

// ---- (7) enterprise coexistence ---------------------------------------------

test("enterprise-envelope notes for the same wallet are discovered beside consumer notes", async () => {
  // An enterprise transfer: receiver ct ECDH-encrypted to the SPEND key, no
  // viewTags — the pre-consumer wire format.
  const entShared = ecdhSharedSecret(EPH, ME.keypair.publicKey);
  const entCt = poseidonEncrypt([321n, 7001n], entShared, NONCE);
  const entLeaf = commitment(321n, 7001n, ME.keypair.publicKey);
  const otherCt = poseidonEncrypt([5n, 5n], ecdhSharedSecret(EPH, STRANGER.keypair.publicKey), NONCE + 1n);
  const entEv: FeedEvent = {
    seq: 0,
    txHash: "0xent",
    blockNumber: 1,
    kind: "transfer",
    epoch: 0,
    ecdhPublicKey: [dec(EPH_PUB[0]), dec(EPH_PUB[1])],
    encryptionNonce: dec(NONCE),
    slices: [
      { offset: 0, elts: 4, leafIndex: 0 },
      { offset: 4, elts: 4, leafIndex: 1 },
      { offset: 8, elts: 16, leafIndex: null }, // authority envelope tail
    ],
    ciphertext: [...entCt, ...otherCt, ...Array.from({ length: 16 }, () => 9n)].map(dec),
  };

  const conSeal = sealTo(ME, 600n, 5001n, 0, 3);
  const conLeaf = commitment(600n, 5001n, ME.keypair.publicKey);
  const conEv = transferPrivEvent({ seq: 1, txHash: "0xcon", leaves: [2, 3], seals: [conSeal, sealTo(STRANGER, 1n, 1n, 1, 4)] });

  const tree = new ImtTree(8, 4);
  tree.appendLeaf(entLeaf);
  tree.appendLeaf(commitment(5n, 5n, STRANGER.keypair.publicKey));
  tree.appendLeaf(conLeaf);
  tree.appendLeaf(commitment(1n, 1n, STRANGER.keypair.publicKey));

  const state = await runSelfScan(mockIo([entEv, conEv], tree), ME);
  assert.equal(state.notes.length, 2, "both families' notes are discovered in one scan");
  const byLeaf = new Map(state.notes.map((n) => [n.leafIndex, n]));
  assert.equal(byLeaf.get(0)?.value, "321");
  assert.equal(byLeaf.get(0)?.family, "enterprise");
  assert.equal(byLeaf.get(2)?.value, "600");
  assert.equal(byLeaf.get(2)?.family, "consumer");
});

test("an enterprise DISBURSE-batch interior (422-gated /path) surfaces as pending, retained across scans", async () => {
  // An enterprise disburse batch: per-recipient 4-elt slices at interior
  // leaves. Its /path is 422-gated in public mode by design — the wallet can
  // decrypt its slice but cannot path-confirm it without an arbiter indexer,
  // so the money must surface as PENDING, never silently drop.
  const entCt = poseidonEncrypt([77n, 9001n], ecdhSharedSecret(EPH, ME.keypair.publicKey), NONCE);
  const otherCt = poseidonEncrypt([5n, 5n], ecdhSharedSecret(EPH, STRANGER.keypair.publicKey), NONCE + 1n);
  const ev: FeedEvent = {
    seq: 4,
    txHash: "0xentbatch",
    blockNumber: 5,
    kind: "disburse",
    epoch: 1,
    ecdhPublicKey: [dec(EPH_PUB[0]), dec(EPH_PUB[1])],
    encryptionNonce: dec(NONCE),
    slices: [
      { offset: 0, elts: 4, leafIndex: 16 },
      { offset: 4, elts: 4, leafIndex: 17 },
    ],
    ciphertext: [...entCt, ...otherCt].map(dec),
  };
  const tree = new ImtTree(8, 4);
  const io: SelfScanIo = {
    ...mockIo([ev], tree),
    path: async () => {
      throw new Error("http://indexer/path/16 -> 422: leaf inside a disburse batch");
    },
  };
  const first = await runSelfScan(io, ME);
  assert.equal(first.notes.length, 0);
  assert.deepEqual(first.pending, [{ seq: 4, txHash: "0xentbatch", batchId: null, status: "enterprise-batch-gated" }]);
  // Retained: the seq is re-read next scan and, still gated, stays pending —
  // "there may be money here an arbiter indexer can open" keeps being said.
  const second = await runSelfScan(io, ME, first);
  assert.deepEqual(second.pending, first.pending);
  assert.equal(second.notes.length, 0);
});

// ---- (8) the REAL consumer fixture ------------------------------------------

test("the committed depositPriv realproof fixture opens with the shared fixture identity", async () => {
  // publics (16): [0]=out [1..2]=ecdhPub [3..10]=cipherTexts[2][4]
  //               [11..12]=viewTags [13..14]=oc [15]=nonce (OPMOD §2)
  const fx = JSON.parse(readFileSync(FIXTURE, "utf8")).depositPriv as {
    pub: string[];
    kemCiphertexts: string[];
  };
  const pub = fx.pub.map(BigInt);
  const ev: FeedEvent = {
    seq: 0,
    txHash: "0xfixture",
    blockNumber: 1,
    kind: "depositPriv",
    epoch: null,
    ecdhPublicKey: [dec(pub[1]), dec(pub[2])],
    encryptionNonce: dec(pub[15]),
    slices: [
      { offset: 0, elts: 4, leafIndex: 0 },
      { offset: 4, elts: 4, leafIndex: 1 },
    ],
    ciphertext: pub.slice(3, 11).map(dec),
    viewTags: [dec(pub[11]), dec(pub[12])],
    kemCiphertexts: fx.kemCiphertexts,
  };
  const tree = new ImtTree(8, 4);
  tree.appendLeaf(pub[13]);
  tree.appendLeaf(pub[14]);

  // consumerReceiver(0) is the fixture plan's first recipient (1000 kKRW);
  // its identity comes from the SAME shared lib the witness inputs derive from.
  const r0 = consumerReceiver(0);
  const identity: ConsumerWalletIdentity = {
    keypair: r0.spend,
    compressedPubkey: packPubkey(r0.spend.publicKey),
    viewKeypair: r0.view,
    compressedViewPubkey: packPubkey(r0.view.publicKey),
    kemKeypair: { ek: r0.kem.publicKey, dk: r0.kem.secretKey },
  };
  assert.ok(isConsumerIdentity(identity));

  const state = await runSelfScan(mockIo([ev], tree), identity);
  assert.equal(state.notes.length, 1, "the fixture recipient discovers exactly its own output");
  assert.equal(state.notes[0].value, "1000");
  assert.equal(state.notes[0].leafIndex, 0);
  assert.equal(state.notes[0].commitment, dec(pub[13]), "leaf-match against the proof's outputCommitment");
});

// ---- (9) activity, snapshot, codec ------------------------------------------

test("activity derivation: one row per op event, kind-mapped, newest-first", () => {
  const notes = [
    { value: "600", salt: "1", leafIndex: 0, commitment: "10", nullifier: "20", txHash: "0xa", spent: false, seq: 0, kind: "transferPriv", family: "consumer" },
    { value: "1000", salt: "2", leafIndex: 2, commitment: "11", nullifier: "21", txHash: "0xb", spent: false, seq: 1, kind: "depositPriv", family: "consumer" },
    { value: "40", salt: "3", leafIndex: 3, commitment: "12", nullifier: "22", txHash: "0xb", spent: false, seq: 1, kind: "depositPriv", family: "consumer" },
    { value: "7", salt: "4", leafIndex: 4, commitment: "13", nullifier: "23", txHash: "0xc", spent: true, seq: 2, kind: "withdrawPriv", family: "consumer" },
  ] as const;
  const rows = deriveScanActivity([...notes]);
  assert.deepEqual(
    rows.map((r) => [r.seq, r.kind, r.amount]),
    [
      [2, "withdraw", "7"],
      [1, "deposit", "1040"],
      [0, "received", "600"],
    ],
    "grouped by event, amounts summed, seq desc",
  );
  assert.ok(rows.every((r) => r.counterparty === null));
});

test("selfScanSnapshot serves the arbiter snapshot shape (owner from the compressed pubkey)", () => {
  const state: SelfScanState = {
    v: 1,
    cursor: 3,
    scannedNextLeafIndex: 4,
    notes: [
      { value: "600", salt: "5001", leafIndex: 0, commitment: "10", nullifier: "20", txHash: "0xa", spent: false, seq: 0, kind: "transferPriv", family: "consumer" },
    ],
    pending: [],
  };
  const snap = selfScanSnapshot(state, ME.compressedPubkey);
  assert.equal(snap.notes.length, 1);
  assert.deepEqual(snap.notes[0].owner, [dec(ME.keypair.publicKey[0]), dec(ME.keypair.publicKey[1])]);
  assert.equal(snap.notes[0].value, "600");
  assert.equal(snap.historyNextBefore, null);
  assert.equal(snap.history.length, 1);
  assert.equal(sumUnspent(snap.notes), 600n);
});

test("scan-state codec: round trip, and anything malformed decodes to null (full rescan)", () => {
  const state: SelfScanState = {
    v: 1,
    cursor: 5,
    scannedNextLeafIndex: 8,
    notes: [],
    pending: [{ seq: 3, txHash: "0xb", batchId: 16, status: "withheld" }],
  };
  assert.deepEqual(decodeScanState(encodeScanState(state)), state);
  assert.equal(decodeScanState(null), null);
  assert.equal(decodeScanState("not json"), null);
  assert.equal(decodeScanState('{"v":2,"cursor":0}'), null);
  assert.equal(decodeScanState('{"v":1,"cursor":"x","scannedNextLeafIndex":0,"notes":[],"pending":[]}'), null);
  assert.deepEqual(decodeScanState(encodeScanState(EMPTY_SCAN_STATE)), EMPTY_SCAN_STATE);
});
