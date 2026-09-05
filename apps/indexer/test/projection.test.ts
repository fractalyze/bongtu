// Per-op feed projection unit test — CPU lane, table-driven, no store, no
// tree, no Postgres. Pins the exact FeedEntry draft every projected op kind
// produces (src/projection.ts), so a feed-shape change is a deliberate diff
// against THIS table rather than a drift between the two rail ladders. The
// enterprise disburse is deliberately absent: the rails genuinely diverge
// there and keep their own branches (EVM bakes slices/ciphertext + the
// verifyDisclosure verdict; Solana serves institution-held bytes with a
// registry verdict + a rail-only disburseAnchor).
//
//   node --import tsx --test test/projection.test.ts   # (== npm run test:projection)

import { test } from "node:test";
import assert from "node:assert/strict";

import { projectFeedEntry, type OpProjection } from "../src/projection.js";
import type { FeedEntry } from "../src/store.js";
import type { DisclosureResult } from "../src/disclosure.js";

const AT = { txHash: "0xfeed", blockNumber: 7, logIndex: 3 };
const POS = AT; // one literal: every want spreads POS, every call passes AT
const ECDH: [bigint, bigint] = [11n, 22n];
const NONCE = 999n;
const ANN = { recipient: "0x" + "1".repeat(40), ephemeralPub: "0x" + "2".repeat(64), viewTag: 77 };

// A consumer-disburse verdict as verifyConsumerDisclosure would return it —
// the projection passes it through untouched (computed rail-side; it needs
// the subtreeRoot correlation the rails own).
const VERDICT: DisclosureResult = {
  status: "verified",
  txHash: AT.txHash,
  startLeafIndex: 16,
  emittedCount: 24,
  receiverCount: 16,
  recomputed: "42",
  expected: "42",
};

const seq = (n: number, from = 0): bigint[] => Array.from({ length: n }, (_, i) => BigInt(from + i));
const decs = (xs: bigint[]): string[] => xs.map((x) => x.toString());

// B=4 disbursePriv material: disclosure = receiverCts[4B] ++ viewTags[B] ++
// outputCommitments[B], element i carrying value i for offset-visible pins.
const B = 4;
const FULL_DISCLOSURE = seq(6 * B);

interface Row {
  name: string;
  op: OpProjection;
  want: Omit<FeedEntry, "seq">;
}

// THE pinned table: one row per projected shape (every kind + both optional
// postures). `want` objects OMIT keys the draft must not carry —
// deepStrictEqual distinguishes an absent key from key: undefined, so the
// optional-field rules are pinned too.
const rows: Row[] = [
  {
    name: "deposit: bare entry (envelope bytes are arbiter-ledger material, never public feed)",
    op: { kind: "deposit" },
    want: {
      ...POS, kind: "deposit", epoch: null,
      ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
    },
  },
  {
    name: "withdraw without announcement: bare entry, announcement key ABSENT (EVM attaches later via its queue)",
    op: { kind: "withdraw" },
    want: {
      ...POS, kind: "withdraw", epoch: null,
      ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
    },
  },
  {
    name: "withdraw with inline announcement (Solana posture): attached verbatim",
    op: { kind: "withdraw", announcement: ANN },
    want: {
      ...POS, kind: "withdraw", epoch: null,
      ecdhPublicKey: null, encryptionNonce: null, slices: [], ciphertext: [],
      announcement: ANN,
    },
  },
  {
    name: "transfer: 2 receiver slices + a 16-elt authority tail slice; epoch is the caller's input",
    op: {
      kind: "transfer", epoch: 5,
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      outputLeafIndices: [40, 41],
      receiverCts: seq(8, 100),
      authorityCt: seq(16, 200),
    },
    want: {
      ...POS, kind: "transfer", epoch: 5,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [
        { offset: 0, elts: 4, leafIndex: 40 },
        { offset: 4, elts: 4, leafIndex: 41 },
        { offset: 8, elts: 16, leafIndex: null },
      ],
      ciphertext: [...decs(seq(8, 100)), ...decs(seq(16, 200))],
    },
  },
  {
    name: "transfer10: ten receiver slices, tail slice offset/elts derive from the arrays",
    op: {
      kind: "transfer10", epoch: 0,
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      outputLeafIndices: Array.from({ length: 10 }, (_, i) => 50 + i),
      receiverCts: seq(40, 1000),
      authorityCt: seq(64, 2000), // the real Transferred10 tail arity (pool ABI)
    },
    want: {
      ...POS, kind: "transfer10", epoch: 0,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [
        ...Array.from({ length: 10 }, (_, i) => ({ offset: i * 4, elts: 4, leafIndex: 50 + i })),
        { offset: 40, elts: 64, leafIndex: null },
      ],
      ciphertext: [...decs(seq(40, 1000)), ...decs(seq(64, 2000))],
    },
  },
  {
    name: "transfer10x2: 2 outputs, 31-elt authority tail (length derives from the input array)",
    op: {
      kind: "transfer10x2", epoch: 9,
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      outputLeafIndices: [60, 61],
      receiverCts: seq(8, 300),
      authorityCt: seq(31, 400),
    },
    want: {
      ...POS, kind: "transfer10x2", epoch: 9,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [
        { offset: 0, elts: 4, leafIndex: 60 },
        { offset: 4, elts: 4, leafIndex: 61 },
        { offset: 8, elts: 31, leafIndex: null },
      ],
      ciphertext: [...decs(seq(8, 300)), ...decs(seq(31, 400))],
    },
  },
  // The one consumer-small arm, exercised per kind (OPMOD §3.6 shape: two
  // output slices, viewTags to decimal, kem cts pass through as 0x-hex).
  ...(["depositPriv", "transferPriv", "transfer10x2Priv"] as const).map((kind): Row => ({
    name: `${kind}: two 4-elt slices, viewTags decimal, kem cts verbatim, epoch null`,
    op: {
      kind,
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      outputLeafIndices: [8, 9],
      cts: seq(8, 500),
      viewTags: [12n, 200n],
      kemCiphertexts: ["0xaa", "0xbb"],
    },
    want: {
      ...POS, kind, epoch: null,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [
        { offset: 0, elts: 4, leafIndex: 8 },
        { offset: 4, elts: 4, leafIndex: 9 },
      ],
      ciphertext: decs(seq(8, 500)),
      viewTags: ["12", "200"],
      kemCiphertexts: ["0xaa", "0xbb"],
    },
  })),
  {
    name: "withdrawPriv without announcement (EVM posture): one change slice, key ABSENT",
    op: {
      kind: "withdrawPriv",
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      changeLeafIndex: 13,
      cts: seq(4, 600),
      viewTags: [7n],
      kemCiphertexts: ["0xcc"],
    },
    want: {
      ...POS, kind: "withdrawPriv", epoch: null,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [{ offset: 0, elts: 4, leafIndex: 13 }],
      ciphertext: decs(seq(4, 600)),
      viewTags: ["7"],
      kemCiphertexts: ["0xcc"],
    },
  },
  {
    name: "withdrawPriv with inline announcement (Solana posture): attached verbatim",
    op: {
      kind: "withdrawPriv",
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      changeLeafIndex: 13,
      cts: seq(4, 600),
      viewTags: [7n],
      kemCiphertexts: ["0xcc"],
      announcement: ANN,
    },
    want: {
      ...POS, kind: "withdrawPriv", epoch: null,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [{ offset: 0, elts: 4, leafIndex: 13 }],
      ciphertext: decs(seq(4, 600)),
      viewTags: ["7"],
      kemCiphertexts: ["0xcc"],
      announcement: ANN,
    },
  },
  {
    name: "disbursePriv FULL: B slices + viewTags + outputCommitments carved from the 6B disclosure run",
    op: {
      kind: "disbursePriv",
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      startLeafIndex: 16, batchSize: B,
      disclosure: FULL_DISCLOSURE,
      verdict: VERDICT,
    },
    want: {
      ...POS, kind: "disbursePriv", epoch: null,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: Array.from({ length: B }, (_, i) => ({ offset: i * 4, elts: 4, leafIndex: 16 + i })),
      ciphertext: decs(FULL_DISCLOSURE.slice(0, 4 * B)),
      disclosure: VERDICT,
      viewTags: decs(FULL_DISCLOSURE.slice(4 * B, 5 * B)),
      outputCommitments: decs(FULL_DISCLOSURE.slice(5 * B, 6 * B)),
      batchId: 16,
    },
  },
  {
    name: "disbursePriv WITHHELD (empty disclosure): no slices, no viewTags/outputCommitments keys, batchId still set",
    op: {
      kind: "disbursePriv",
      ecdhPublicKey: ECDH, encryptionNonce: NONCE,
      startLeafIndex: 16, batchSize: B,
      disclosure: [],
      verdict: { ...VERDICT, status: "withheld", emittedCount: 0, recomputed: "0" },
    },
    want: {
      ...POS, kind: "disbursePriv", epoch: null,
      ecdhPublicKey: ["11", "22"], encryptionNonce: "999",
      slices: [],
      ciphertext: [],
      disclosure: { ...VERDICT, status: "withheld", emittedCount: 0, recomputed: "0" },
      batchId: 16,
    },
  },
];

for (const row of rows) {
  test(row.name, () => {
    assert.deepStrictEqual(projectFeedEntry(AT, row.op), row.want);
  });
}

test("the table covers every projected kind (the enterprise disburse is excluded by design)", () => {
  const covered = new Set<string>(rows.map((r) => r.op.kind));
  const projected: FeedEntry["kind"][] = [
    "deposit", "withdraw", "transfer", "transfer10", "transfer10x2",
    "depositPriv", "transferPriv", "transfer10x2Priv", "withdrawPriv", "disbursePriv",
  ];
  for (const k of projected) assert.ok(covered.has(k), `no table row for kind ${k}`);
  assert.ok(!covered.has("disburse"), "the enterprise disburse must NOT be projected here");
});

test("optional keys are ABSENT (not undefined) when their rule does not fire", () => {
  const bareWithdraw = projectFeedEntry(AT, { kind: "withdraw" });
  assert.ok(!("announcement" in bareWithdraw), "withdraw without input carries no announcement key");
  const withheld = projectFeedEntry(AT, {
    kind: "disbursePriv", ecdhPublicKey: ECDH, encryptionNonce: NONCE,
    startLeafIndex: 16, batchSize: B, disclosure: [], verdict: { ...VERDICT, status: "withheld" },
  });
  assert.ok(!("viewTags" in withheld) && !("outputCommitments" in withheld),
    "a non-full disclosure run projects no viewTags/outputCommitments keys");
});
