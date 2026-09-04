// Headless gates for the PURE consumer witness builders (src/consumerBuild.ts).
// The gate that matters most is the FIXTURE PIN: for each of the four CPU
// consumer circuits, the builder — driven with the SAME deterministic
// parameters the committed fixture generator used (circuits/fixtures/
// consumer_lib.ts + gen_consumer_inputs.ts are PRNG-free: every scalar, salt,
// nonce and KEM encapsulation seed is index-derived, so reproduction is exact
// by construction, never a re-draw) — must rebuild the committed
// circuits/fixtures/inputs/<name>.json byte-for-byte. That equality is what
// proves the wallet's witness assembly and the proven-against-real-artifacts
// fixture pipeline are the same math.
//
// The pin assemblies are built ONCE at module scope (each runs two ML-KEM
// encapsulations plus an IMT build) and every clause below property-checks the
// same objects — the payroll-suite rationalization rule.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { kemBytesToHex } from "@bongtu/core/kem";
import { commitment } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";

import {
  buildConsumerDepositRequest,
  buildConsumerTransfer10x2Request,
  buildConsumerTransferRequest,
  buildConsumerWithdrawRequest,
  consumerCircuitOf,
  consumerRecipientOf,
  freshConsumerDepositCrypto,
  freshConsumerSpendCrypto,
  selfConsumerRecipient,
} from "@bongtu/client/consumerBuild";
import type { ConsumerRecipient, ConsumerSpendCrypto } from "@bongtu/client/consumerBuild";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import type { MembershipWitness } from "@bongtu/client/spend";

import {
  CONSUMER_SENDER,
  consumerReceiver,
  encapSeed,
} from "../../../circuits/fixtures/consumer_lib.js";
import type { ConsumerIdentity } from "../../../circuits/fixtures/consumer_lib.js";
import {
  ECDH_SK,
  ENCRYPTION_NONCE,
  membership,
  salt,
} from "../../../circuits/fixtures/fixture_lib.js";
import type { Membership } from "../../../circuits/fixtures/fixture_lib.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const INPUTS = join(HERE, "..", "..", "..", "circuits", "fixtures", "inputs");
const fixture = (name: string): unknown =>
  JSON.parse(readFileSync(join(INPUTS, `${name}.json`), "utf8"));

// The fixture identities in the two shapes the engine consumes: the spender as
// a ConsumerWalletIdentity, each payee as the registry-triple ConsumerRecipient.
const asWallet = (id: ConsumerIdentity): ConsumerWalletIdentity => ({
  keypair: id.spend,
  compressedPubkey: packPubkey(id.spend.publicKey),
  viewKeypair: id.view,
  compressedViewPubkey: packPubkey(id.view.publicKey),
  kemKeypair: { ek: id.kem.publicKey, dk: id.kem.secretKey },
});
const asRecipient = (id: ConsumerIdentity): ConsumerRecipient => ({
  owner: packPubkey(id.spend.publicKey),
  noteViewPub: packPubkey(id.view.publicKey),
  kemEk: kemBytesToHex(id.kem.publicKey),
});

const SENDER_W = asWallet(CONSUMER_SENDER);
const SPEND_PUB = CONSUMER_SENDER.spend.publicKey;
const REC0 = asRecipient(consumerReceiver(0));
const REC1 = asRecipient(consumerReceiver(1));

// fixture_lib membership() (the generator's own IMT) reshaped into the
// per-input witness the engine takes from GET /path.
const wit = (m: Membership): MembershipWitness[] =>
  m.leafIndices.map((li, i) => ({
    root: m.root.toString(),
    pathElements: m.pathElements[i].map(String),
    leafIndex: Number(li),
  }));

const note = (value: bigint, s: bigint, leafIndex: number) => ({
  value: value.toString(),
  salt: s.toString(),
  leafIndex,
});

const seeds = (label: string, n: number): Uint8Array[] =>
  Array.from({ length: n }, (_, i) => encapSeed(label, i));

const spendCrypto = (over: Partial<ConsumerSpendCrypto>): ConsumerSpendCrypto => ({
  ecdhPrivateKey: ECDH_SK.toString(),
  encryptionNonce: ENCRYPTION_NONCE.toString(),
  changeSalt: salt(1).toString(),
  padSalts: [],
  ...over,
});

// ===================== the four pin assemblies (built ONCE) ==================

// depositPriv: mint 1000 -> receiver(0) + 2000 -> receiver(1) (both third
// parties) — consumer_lib depositPrivPlan.
const DEP = buildConsumerDepositRequest(
  [
    { recipient: REC0, value: "1000" },
    { recipient: REC1, value: "2000" },
  ],
  {
    ecdhPrivateKey: ECDH_SK.toString(),
    encryptionNonce: ENCRYPTION_NONCE.toString(),
    salt0: salt(0).toString(),
    salt1: salt(1).toString(),
    encapSeeds: seeds("depositPriv", 2),
  },
);

// transferPriv: spend [700, 300] -> pay 600 to receiver(0), 400 change —
// gen_consumer_inputs genTransferPriv + consumer_lib transferPrivPlan.
const TRF_NOTES = [note(700n, salt(10), 0), note(300n, salt(11), 1)];
const TRF_WIT = wit(
  membership([commitment(700n, salt(10), SPEND_PUB), commitment(300n, salt(11), SPEND_PUB)]),
);
const TRF_CRYPTO = spendCrypto({
  payeeSalt: salt(0).toString(),
  changeSalt: salt(1).toString(),
  encapSeeds: seeds("transferPriv", 2),
});
const TRF = buildConsumerTransferRequest(SENDER_W, TRF_NOTES, TRF_WIT, REC0, "600", TRF_CRYPTO);

// transfer10x2Priv: 4 real inputs [400, 300, 200, 100] + 6 pads -> pay 700 to
// receiver(0), 300 change — genTransfer10x2Priv.
const T10_VALUES = [400n, 300n, 200n, 100n];
const T10_SALTS = T10_VALUES.map((_, i) => salt(100 + i));
const T10 = buildConsumerTransfer10x2Request(
  SENDER_W,
  T10_VALUES.map((v, i) => note(v, T10_SALTS[i], i)),
  wit(membership(T10_VALUES.map((v, i) => commitment(v, T10_SALTS[i], SPEND_PUB)))),
  REC0,
  "700",
  spendCrypto({
    payeeSalt: salt(110).toString(),
    changeSalt: salt(111).toString(),
    padSalts: Array.from({ length: 6 }, (_, i) => salt(80 + i).toString()),
    encapSeeds: seeds("transfer10x2Priv", 2),
  }),
);

// withdrawPriv: spend [600, 500] -> push 1000 ERC-20 to the fixture recipient,
// 100 change — genWithdrawPriv.
const WDR = buildConsumerWithdrawRequest(
  SENDER_W,
  [note(600n, salt(20), 0), note(500n, salt(21), 1)],
  wit(membership([commitment(600n, salt(20), SPEND_PUB), commitment(500n, salt(21), SPEND_PUB)])),
  "1000",
  spendCrypto({ changeSalt: salt(0).toString(), encapSeeds: seeds("withdrawPriv", 1) }),
  "0x1111111111111111111111111111111111111111",
);

// ======================= (1) FIXTURE PINS ====================================

const PINS = [
  { name: "depositPriv", request: DEP.request },
  { name: "transferPriv", request: TRF.request },
  { name: "transfer10x2Priv", request: T10.request },
  { name: "withdrawPriv", request: WDR.request },
] as const;

for (const { name, request } of PINS) {
  test(`FIXTURE PIN: ${name} builder reproduces circuits/fixtures/inputs/${name}.json exactly`, () => {
    assert.equal(request.circuit, name);
    assert.equal(request.backend, "cpu");
    // deep equality against the COMMITTED file: same fields, same wire values —
    // the witness the wallet would prove is the witness the artifacts proved.
    assert.deepStrictEqual(request.input, fixture(name));
    // and it survives the wire (POST-able to a prover; no bigints leak).
    assert.deepStrictEqual(JSON.parse(JSON.stringify(request)).input, fixture(name));
  });
}

// ================== (2) INTERFACE PROPERTIES (same assemblies) ===============

test("value conservation: outputs (+ withdrawn amount) == real input total; deposit outputs == amount", () => {
  const sum = (xs: string[]): bigint => xs.reduce((a, x) => a + BigInt(x), 0n);
  assert.equal(sum(DEP.meta.outputValues), 3000n);
  assert.equal(DEP.meta.amount, "3000");
  for (const [meta, withdrawn] of [
    [TRF.meta, 0n],
    [T10.meta, 0n],
    [WDR.meta, 1000n],
  ] as const) {
    assert.equal(sum(meta.outputValues) + withdrawn, BigInt(meta.inputTotal));
    assert.equal(meta.membershipOk, true, "every real input folds to the shared root");
  }
});

test("padding arity per op: input slots filled to the circuit's width, pads disabled and distinct", () => {
  // 2-arity ops carry exactly 2 input slots, fully real here.
  for (const req of [TRF.request, WDR.request]) {
    assert.equal(req.input.nullifiers.length, 2);
    assert.deepEqual(req.input.enabled, ["1", "1"]);
  }
  // the 10-arity op pads 4 real inputs up to 10: pad slots carry nullifier 0,
  // value 0, enabled 0, a zeros path — and a NONZERO value-0 commitment each on
  // its own salt, so no two pads collide.
  const x = T10.request.input;
  assert.equal(x.nullifiers.length, 10);
  assert.deepEqual(x.enabled, [..."1111".split(""), ..."000000".split("")]);
  assert.deepEqual(x.nullifiers.slice(4), Array.from({ length: 6 }, () => "0"));
  const padCommits = x.inputCommitments.slice(4) as string[];
  assert.equal(new Set(padCommits).size, 6, "pad commitments are pairwise distinct");
  for (const c of padCommits) assert.notEqual(c, "0");
  for (const path of x.pathElements.slice(4)) {
    assert.deepEqual(path, Array.from({ length: 32 }, () => "0"));
  }
  // outputs stay at 2 (payment + change) for both transfer arities, 1 for withdraw.
  assert.equal(x.outputCommitments.length, 2);
  assert.equal(WDR.request.input.outputCommitments.length, 1);
});

test("outputs are sealed to the right identities: payment -> the recipient triple, change -> self", () => {
  const point = (p: readonly [bigint, bigint]): [string, string] => [
    p[0].toString(),
    p[1].toString(),
  ];
  const rec0 = consumerReceiver(0);
  const t = TRF.request.input;
  // output 0 binds the RECIPIENT's spend key (funds) and seals to their VIEW key
  // (discovery) — the view/spend split that makes a scanner unable to spend.
  assert.deepEqual(t.outputOwnerPublicKeys[0], point(rec0.spend.publicKey));
  assert.deepEqual(t.outputViewPublicKeys[0], point(rec0.view.publicKey));
  // output 1 (change) binds the WALLET's own pair — recovered later by self-scan.
  assert.deepEqual(t.outputOwnerPublicKeys[1], point(CONSUMER_SENDER.spend.publicKey));
  assert.deepEqual(t.outputViewPublicKeys[1], point(CONSUMER_SENDER.view.publicKey));
  // the deposit's two third-party outputs are two DISTINCT identities.
  const d = DEP.request.input;
  assert.notDeepEqual(d.outputOwnerPublicKeys[0], d.outputOwnerPublicKeys[1]);
  assert.notDeepEqual(d.outputViewPublicKeys[0], d.outputViewPublicKeys[1]);
  // and each result carries one kem ct per output for the tx calldata.
  assert.equal(DEP.meta.kemCiphertexts.length, 2);
  assert.equal(WDR.meta.kemCiphertexts.length, 1);
  for (const ct of DEP.meta.kemCiphertexts) assert.match(ct, /^0x[0-9a-f]{2176}$/);
});

test("without injected seeds, two builds share structure but never a seal (fresh KEM per call)", () => {
  const crypto = spendCrypto({ payeeSalt: salt(0).toString(), changeSalt: salt(1).toString() });
  const a = buildConsumerTransferRequest(SENDER_W, TRF_NOTES, TRF_WIT, REC0, "600", crypto);
  const b = buildConsumerTransferRequest(SENDER_W, TRF_NOTES, TRF_WIT, REC0, "600", crypto);
  // the note algebra is deterministic in the note parameters…
  assert.deepStrictEqual(a.request.input.outputCommitments, b.request.input.outputCommitments);
  assert.deepStrictEqual(a.request.input.nullifiers, b.request.input.nullifiers);
  // …but every call encapsulates FRESH: shared-secret limbs and tx cts differ
  // (ct reuse across txs would collapse the PQ compartment).
  assert.notDeepStrictEqual(a.request.input.kemSs, b.request.input.kemSs);
  assert.notDeepStrictEqual(a.meta.kemCiphertexts, b.meta.kemCiphertexts);
});

// ========================= (3) PER-TX CRYPTO =================================

test("freshConsumerSpendCrypto draws 13 distinct fields, deposit draws 4 — never a recipient key", () => {
  const draws = { n: 0 };
  const rand = (): string => String(++draws.n * 1111);
  const s = freshConsumerSpendCrypto(rand);
  assert.equal(draws.n, 13); // ecdh, nonce, payee salt, change salt, 9 pad salts
  assert.equal(
    new Set([s.ecdhPrivateKey, s.encryptionNonce, s.payeeSalt, s.changeSalt, ...s.padSalts]).size,
    13,
    "no two fields share a draw (two-time-pad guard)",
  );
  assert.equal(s.encapSeeds, undefined, "production never pre-draws encapsulation randomness");
  const before = draws.n;
  const d = freshConsumerDepositCrypto(rand);
  assert.equal(draws.n - before, 4); // ecdh, nonce, salt0, salt1
  assert.equal(new Set([d.ecdhPrivateKey, d.encryptionNonce, d.salt0, d.salt1]).size, 4);
});

test("both crypto draws clamp the nonce below 2^128 and keep salts full-width", () => {
  // SymmetricEncrypt constrains nonce < 2^128; the per-output +i can still
  // land in the residual [2^128-255, 2^128) range, where offsetNonce throws
  // loudly (retryable, ~2^-121) — the clamp guards the slot, not the offset.
  const wide = ((1n << 247n) + 12345n).toString();
  const s = freshConsumerSpendCrypto(() => wide);
  const d = freshConsumerDepositCrypto(() => wide);
  for (const c of [s.encryptionNonce, d.encryptionNonce]) assert.ok(BigInt(c) < 1n << 128n);
  assert.equal(s.changeSalt, wide, "salts keep the full draw");
  assert.equal(d.salt0, wide, "salts keep the full draw");
  assert.equal(s.ecdhPrivateKey, wide, "the ephemeral key keeps the full draw");
});

// ==================== (4) RECIPIENTS, ROUTING, GUARDS ========================

test("consumerRecipientOf accepts only a live v2 consumer pair; selfConsumerRecipient round-trips", () => {
  const base = {
    name: "alice",
    owner: REC0.owner,
    viewPub: "0x" + "11".repeat(32),
    spendPub: "0x" + "22".repeat(33),
    updatedAt: 0,
  };
  const v2 = { ...base, noteViewPub: REC0.noteViewPub, kemEk: REC0.kemEk };
  assert.deepEqual(consumerRecipientOf(v2), REC0);
  // a legacy record and a signed zero-sentinel clear are both "cannot receive".
  assert.throws(() => consumerRecipientOf(base), /no consumer identity/);
  assert.throws(
    () =>
      consumerRecipientOf({
        ...base,
        noteViewPub: "0x" + "0".repeat(64),
        kemEk: "0x" + "0".repeat(2368),
      }),
    /no consumer identity/,
  );
  // the wallet's own triple is exactly the triple a registry v2 write would carry.
  assert.deepEqual(selfConsumerRecipient(SENDER_W), asRecipient(CONSUMER_SENDER));
});

test("consumerCircuitOf maps the reused enterprise auto-pick onto the consumer family", () => {
  assert.deepEqual(
    (["transfer", "transfer10x2", "withdraw"] as const).map(consumerCircuitOf),
    ["transferPriv", "transfer10x2Priv", "withdrawPriv"],
  );
});

test("guards reject a doomed op before any sealing or proving", () => {
  const dep = { ecdhPrivateKey: "1", encryptionNonce: "2", salt0: "3", salt1: "4" };
  assert.throws(() => buildConsumerDepositRequest([{ recipient: REC0, value: "1" }], dep), /exactly 2/);
  assert.throws(
    () =>
      buildConsumerDepositRequest(
        [
          { recipient: REC0, value: "0" },
          { recipient: REC1, value: "0" },
        ],
        dep,
      ),
    /positive/,
  );
  const crypto = spendCrypto({ payeeSalt: "5" });
  assert.throws(
    () => buildConsumerTransferRequest(SENDER_W, TRF_NOTES, TRF_WIT, REC0, "0", crypto),
    /positive/,
  );
  assert.throws(
    () => buildConsumerTransferRequest(SENDER_W, TRF_NOTES, TRF_WIT, REC0, "1001", crypto),
    /exceeds/,
  );
  assert.throws(
    () => buildConsumerWithdrawRequest(SENDER_W, TRF_NOTES, TRF_WIT, "100", crypto, "0x0"),
    /recipient/,
  );
});
