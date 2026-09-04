// Pins + unit gate for the consumer note-layer crypto (OPMOD §3/§4,
// .dev/op-module-design.md) — the TS halves of the S2.1 consumer gates:
//
//   p1  tag freeze: the three consumer domain tags recompute from their ascii
//       strings (sha256 mod r) and never collide with the arbiter tags;
//   p2  hybrid receiver key: recorded vectors on deterministic key material,
//       ECDH symmetry, and cross-family separation from hybridEnvelopeKey;
//   p3  viewTag canonicality (TS half of the S2.1 gate): the low-8-bit mask on
//       recorded vectors, both derivation sides equal, and the alias-sensitive
//       edges ([0, 2^254 − p) and [p − 2^8, p)) where a non-strict in-circuit
//       decomposition (tagField + p) WOULD flip the tag — pinned so Stage C's
//       circuit-vs-TS equality gate has fixed expected values;
//   p4  receiver-ct codec (TS half of the receiver-decrypt parity gate):
//       seal/open round trip on pinned artifacts, the §3.5 nonce+index rule,
//       and leaf-match rejection of wrong-key / junk-KEM decrypts;
//   p5  disclosure fold (TS half of the commitment-publication binding gate):
//       the §4.2 three-run order — cts ++ viewTags ++ commitments — pinned
//       elementwise and as a hash, order-sensitivity, shape validation.
//
// The decimal pins were RECORDED from this implementation on 2026-09-03; they
// exist so any later refactor (or the Stage B/C circuit work) that shifts a
// derivation fails here, in the fast sdk suite, not at the prove gate.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { deriveKeypair, ecdhSharedSecret, commitment } from "@bongtu/core/note";
import {
  kemSsToLimbs,
  ml_kem768,
  hybridEnvelopeKey,
  TAG_K0,
  TAG_K1,
  TAG_BIND,
  KEM_CIPHERTEXT_BYTES,
} from "@bongtu/core/kem";
import {
  TAG_RK0,
  TAG_RK1,
  TAG_VIEWTAG,
  CONSUMER_CT_LEN,
  hybridReceiverKey,
  viewTagFromField,
  consumerViewTag,
  encryptConsumerNote,
  decryptConsumerNote,
  sealConsumerOutput,
  openConsumerOutput,
  consumerDisclosureLen,
  consumerDisclosureElements,
  consumerDisclosureHash,
} from "@bongtu/core/consumer";
import { disclosureChain } from "@bongtu/core/envelope";
import { FIELD_PRIME, poseidonN } from "@bongtu/core/poseidon";

const P = FIELD_PRIME;

// ---- deterministic test material (index-derived, PRNG-free) -----------------

const sha = (label: string): Uint8Array =>
  new Uint8Array(createHash("sha256").update(label).digest());

const VIEW = deriveKeypair(777000777000777n); // recipient note-layer view keypair
const EPH = deriveKeypair(31337313373133731337n); // sender ephemeral
const SPEND = deriveKeypair(999888777666555444n); // recipient spend keypair (leaf-match only)
const KEM = ml_kem768.keygen(
  new Uint8Array([...sha("consumer-test/kem/d"), ...sha("consumer-test/kem/z")]),
);
const ENCAP_SEED = sha("consumer-test/encap/0");
const NONCE = 424242n;

// ---- p1: tag freeze ---------------------------------------------------------

test("p1: the three consumer tags recompute from their ascii strings (sha256 mod r) and match the frozen literals", () => {
  const tagOf = (s: string): bigint =>
    BigInt("0x" + createHash("sha256").update(s, "ascii").digest("hex")) % P;
  assert.equal(tagOf("bongtu/consumer-note/v1/key0"), TAG_RK0);
  assert.equal(tagOf("bongtu/consumer-note/v1/key1"), TAG_RK1);
  assert.equal(tagOf("bongtu/consumer-note/v1/viewtag"), TAG_VIEWTAG);
});

test("p1: consumer and arbiter tag families are pairwise distinct (six tags, no reuse)", () => {
  const tags = [TAG_RK0, TAG_RK1, TAG_VIEWTAG, TAG_K0, TAG_K1, TAG_BIND];
  assert.equal(new Set(tags.map(String)).size, tags.length);
});

// ---- p2: hybrid receiver key ------------------------------------------------

test("p2: hybridReceiverKey matches the recorded vectors on deterministic material", () => {
  const enc = ml_kem768.encapsulate(KEM.publicKey, ENCAP_SEED);
  const limbs = kemSsToLimbs(enc.sharedSecret);
  assert.deepEqual(limbs, [
    193388549464413246438392916092806186586n,
    140403669177535266756080158437739254714n,
  ]);

  const shared = ecdhSharedSecret(EPH.formattedPrivateKey, VIEW.publicKey);
  assert.deepEqual(shared, [
    16599435567369927168076621897006808863224931174655371949804516988636380685895n,
    21360757837499850698028196114298789568812083142942032556114122819222639099974n,
  ]);
  // ECDH symmetry: the recipient's viewPriv against the ephemeral pub is the same point.
  assert.deepEqual(ecdhSharedSecret(VIEW.formattedPrivateKey, EPH.publicKey), shared);

  const rk = hybridReceiverKey(shared, limbs);
  assert.deepEqual(rk, [
    12541821878894437047871701354448048996982261263181619872568935879052914049588n,
    1258138561770929591428035572678062346856106266208818936742480716278182077718n,
  ]);
  // Structural: each half is the tagged Poseidon(5) fold of point + limbs.
  assert.equal(rk[0], poseidonN([TAG_RK0, shared[0], shared[1], limbs[0], limbs[1]]));
  assert.equal(rk[1], poseidonN([TAG_RK1, shared[0], shared[1], limbs[0], limbs[1]]));
  // Cross-family separation: same inputs under the arbiter tags give a different key.
  const arbiterKey = hybridEnvelopeKey(shared, limbs);
  assert.notEqual(rk[0], arbiterKey[0]);
  assert.notEqual(rk[1], arbiterKey[1]);
});

// ---- p3: viewTag canonicality (TS half of the S2.1 gate) --------------------

test("p3: consumerViewTag is the canonical low byte of Poseidon(3)([TAG_VIEWTAG, S]) — pinned, in range, both sides equal", () => {
  const shared = ecdhSharedSecret(EPH.formattedPrivateKey, VIEW.publicKey);
  const tag = consumerViewTag(shared);
  assert.equal(tag, 62n); // recorded
  assert.ok(tag >= 0n && tag < 256n);
  assert.equal(tag, poseidonN([TAG_VIEWTAG, shared[0], shared[1]]) % 256n);
  // Scanner side (viewPriv only — no KEM material involved, OPMOD §3.2).
  assert.equal(consumerViewTag(ecdhSharedSecret(VIEW.formattedPrivateKey, EPH.publicKey)), tag);
});

test("p3: alias-edge vectors — the non-canonical decomposition (tagField + p) always flips the tag", () => {
  // Alias band: tagField in [0, 2^254 − p) admits a second 254-bit decomposition
  // (tagField + p as an integer) under a non-strict Num2Bits(254). p ≡ 1 mod 256,
  // so the alias's low byte is tag + 1 mod 256 — ALWAYS different, which is why
  // Num2Bits_strict is mandatory in-circuit (OPMOD §3.2) and why these exact
  // vectors feed Stage C's circuit-vs-TS canonicality gate.
  const band = (1n << 254n) - P; // width of the aliasable range
  assert.equal(P % 256n, 1n);
  const vectors: Array<[bigint, bigint]> = [
    [0n, 0n],
    [1n, 1n],
    [band - 1n, 254n], // recorded: top of the alias band
    [P - 256n, 1n], // recorded: bottom of the [p − 2^8, p) edge
    [P - 1n, 0n], // recorded: the largest field element
  ];
  for (const [t, want] of vectors) {
    assert.equal(viewTagFromField(t), want, `tagField ${t}`);
  }
  // For every aliasable vector the alternate decomposition disagrees.
  for (const [t] of vectors.filter(([t]) => t < band)) {
    assert.notEqual((t + P) % 256n, viewTagFromField(t), `alias of tagField ${t}`);
  }
  // Canonicality is range-enforced: a non-reduced input is a caller bug, not a tag.
  assert.throws(() => viewTagFromField(P), /out of range/);
  assert.throws(() => viewTagFromField(-1n), /out of range/);
});

// ---- p4: receiver-ct codec (TS half of receiver-decrypt parity) -------------

test("p4: sealConsumerOutput pins its artifacts and openConsumerOutput round-trips them (leaf-match accepts)", () => {
  const sealed = sealConsumerOutput({
    value: 12345n,
    salt: 55555n,
    ephemeralPriv: EPH.formattedPrivateKey,
    viewPub: VIEW.publicKey,
    kemEk: KEM.publicKey,
    encryptionNonce: NONCE,
    index: 1,
    encapSeed: ENCAP_SEED,
  });
  assert.equal(sealed.cipherText.length, CONSUMER_CT_LEN);
  assert.deepEqual(sealed.cipherText, [
    510232266261969851023848440714068777545794334760816731590474653745571089113n,
    2188907301435157968038689151512825709815738484158252470372783973452659233283n,
    18824952632451333610104887765080342510178123494390660003569494113986259262667n,
    21075865242153926070113220995705470457567137462088780506690784338794458610764n,
  ]);
  assert.equal(sealed.viewTag, 62n);
  assert.equal(sealed.kemCiphertext.length, KEM_CIPHERTEXT_BYTES);
  assert.equal(
    createHash("sha256").update(sealed.kemCiphertext).digest("hex"),
    "474cea2ac440f10f4082eac189013396af89656333178cd9975f0ff5f9bb9db2",
  );

  const opened = openConsumerOutput({
    cipherText: sealed.cipherText,
    ecdhPublicKey: EPH.publicKey,
    viewPriv: VIEW.formattedPrivateKey,
    kemDk: KEM.secretKey,
    kemCiphertext: sealed.kemCiphertext,
    encryptionNonce: NONCE,
    index: 1,
  });
  assert.equal(opened.value, 12345n);
  assert.equal(opened.salt, 55555n);
  assert.equal(opened.viewTag, 62n);
  // The MAC substitute: the rebuilt commitment equals the note's leaf.
  assert.equal(
    commitment(opened.value, opened.salt, SPEND.publicKey),
    15884414674187710608816838551119657960592085355467107119641569130574572517383n,
  );
});

test("p4: the §3.5 nonce+index rule — decrypting at the wrong index yields a leaf-match reject, not the note", () => {
  const sealed = sealConsumerOutput({
    value: 12345n,
    salt: 55555n,
    ephemeralPriv: EPH.formattedPrivateKey,
    viewPub: VIEW.publicKey,
    kemEk: KEM.publicKey,
    encryptionNonce: NONCE,
    index: 1,
    encapSeed: ENCAP_SEED,
  });
  const leaf = commitment(12345n, 55555n, SPEND.publicKey);
  const openAt = (index: number): { value: bigint; salt: bigint } =>
    openConsumerOutput({
      cipherText: sealed.cipherText,
      ecdhPublicKey: EPH.publicKey,
      viewPriv: VIEW.formattedPrivateKey,
      kemDk: KEM.secretKey,
      kemCiphertext: sealed.kemCiphertext,
      encryptionNonce: NONCE,
      index,
    });
  // index 0 (the unshifted nonce) decrypts to garbage the leaf-match rejects.
  const wrong = openAt(0);
  assert.notEqual(commitment(wrong.value, wrong.salt, SPEND.publicKey), leaf);
  // The raw codec agrees: encrypt(i=0) != encrypt(i=1) under the same key/nonce.
  const rk = sealed.receiverKey;
  assert.notDeepEqual(
    encryptConsumerNote(12345n, 55555n, rk, NONCE, 0),
    sealed.cipherText,
  );
  assert.deepEqual(decryptConsumerNote(sealed.cipherText, rk, NONCE, 1), [12345n, 55555n]);
});

test("p4: wrong view key and junk KEM ct both surface as leaf-match rejects (no throw — the S3.3 self-sabotage class)", () => {
  const sealed = sealConsumerOutput({
    value: 12345n,
    salt: 55555n,
    ephemeralPriv: EPH.formattedPrivateKey,
    viewPub: VIEW.publicKey,
    kemEk: KEM.publicKey,
    encryptionNonce: NONCE,
    index: 0,
    encapSeed: ENCAP_SEED,
  });
  const leaf = commitment(12345n, 55555n, SPEND.publicKey);

  // Wrong viewPriv: decrypt runs, commitment mismatches.
  const wrongView = openConsumerOutput({
    cipherText: sealed.cipherText,
    ecdhPublicKey: EPH.publicKey,
    viewPriv: deriveKeypair(123123123123n).formattedPrivateKey,
    kemDk: KEM.secretKey,
    kemCiphertext: sealed.kemCiphertext,
    encryptionNonce: NONCE,
    index: 0,
  });
  assert.notEqual(commitment(wrongView.value, wrongView.salt, SPEND.publicKey), leaf);

  // Tampered KEM ct: implicit rejection yields a pseudorandom ss — no throw,
  // wrong key, leaf-match reject.
  const tampered = Uint8Array.from(sealed.kemCiphertext);
  tampered[0] ^= 0xff;
  const junkKem = openConsumerOutput({
    cipherText: sealed.cipherText,
    ecdhPublicKey: EPH.publicKey,
    viewPriv: VIEW.formattedPrivateKey,
    kemDk: KEM.secretKey,
    kemCiphertext: tampered,
    encryptionNonce: NONCE,
    index: 0,
  });
  assert.notEqual(commitment(junkKem.value, junkKem.salt, SPEND.publicKey), leaf);
});

test("p4: codec input validation — ct arity, index range, and the 128-bit nonce slot", () => {
  const rk: [bigint, bigint] = [1n, 2n];
  assert.throws(() => decryptConsumerNote([1n, 2n, 3n], rk, NONCE, 0), /4 elements/);
  assert.throws(() => encryptConsumerNote(1n, 2n, rk, NONCE, -1), /non-negative integer/);
  assert.throws(() => encryptConsumerNote(1n, 2n, rk, NONCE, 1.5), /non-negative integer/);
  // nonce + index escaping the packing slot is the clamp violation §3.5 excludes.
  assert.throws(() => encryptConsumerNote(1n, 2n, rk, (1n << 128n) - 1n, 1), /128-bit nonce slot/);
  assert.deepEqual(decryptConsumerNote(encryptConsumerNote(7n, 8n, rk, (1n << 128n) - 2n, 1), rk, (1n << 128n) - 2n, 1), [7n, 8n]);
});

// ---- p5: disclosure fold (TS half of commitment-publication binding) --------

const CTS = [
  [1n, 2n, 3n, 4n],
  [5n, 6n, 7n, 8n],
] as const;
const TAGS = [9n, 10n] as const;
const COMMITMENTS = [11n, 12n] as const;

test("p5: the §4.2 layout is three contiguous leaf-order runs — cts ++ viewTags ++ commitments", () => {
  assert.deepEqual(
    consumerDisclosureElements(CTS, TAGS, COMMITMENTS),
    [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 11n, 12n],
  );
  assert.equal(consumerDisclosureLen(2), 12);
  assert.equal(consumerDisclosureLen(256), 1536); // the on-chain length check target
});

test("p5: consumerDisclosureHash is the seeded-at-0 Poseidon(2) chain over that layout — pinned, and any permutation differs", () => {
  const h = consumerDisclosureHash(CTS, TAGS, COMMITMENTS);
  assert.equal(h, 17572350077949043848641796466601259552294714052230225960680551801730624202930n); // recorded
  // Same fold primitive as the enterprise disclosureHash (envelope.ts).
  assert.equal(h, disclosureChain(consumerDisclosureElements(CTS, TAGS, COMMITMENTS)));
  // The order is total and consensus: swapping the tag and commitment runs is a different hash…
  assert.notEqual(h, disclosureChain([...CTS.flat(), ...COMMITMENTS, ...TAGS]));
  // …and so is swapping two elements within one run.
  assert.notEqual(h, consumerDisclosureHash(CTS, TAGS, [12n, 11n]));
});

test("p5: fold shape validation — run lengths must agree and every ct is 4 elements", () => {
  assert.throws(() => consumerDisclosureElements([], [], []), /B >= 1/);
  assert.throws(() => consumerDisclosureElements(CTS, [9n], COMMITMENTS), /disagree on B/);
  assert.throws(
    () => consumerDisclosureElements([[1n, 2n, 3n], [5n, 6n, 7n, 8n]], TAGS, COMMITMENTS),
    /ct 0 is 3 elements/,
  );
});
