// Byte-pins + unit gate for the authority-envelope codec (CONSENSUS-CRITICAL).
//
// The authority-envelope plaintext layout and the Poseidon(2) disclosure chain
// must stay byte-identical to what the in-circuit gadgets compute — a layout
// slip passes TS round-trips but breaks auditor decryption of live-chain
// envelopes. The PINS constants below were RECORDED (U-N1 phase 1, main
// 875c179) against the four pre-consolidation encoder copies + the indexer's
// parseEnvelope, each reproduced on the committed fixture material that site
// already used:
//
//   p1.A  apps/admin-web/src/lib/disburse.ts   (assemble.test.ts fixture(3), B=256;
//                                               recorded from the GENUINE function
//                                               output — decrypted ciphertext tail)
//   p1.B  deploy/e2e_orchestrator.ts           (its inline actor material, B=16)
//   p1.C  deploy/giwa_disburse256.ts           (its inline actor material +
//                                               deploy/addresses.91342.json arbiter, B=256)
//   p1.D  apps/indexer/test/scenario.ts        (honest disburse leg == p1.B material,
//                                               plus the disburse#3 authority-tampered
//                                               leg's DISTINCT input shape, B=16)
//   p2    disclosureChain over the ciphertext derived from the committed
//         contracts/test/fixtures/disburse256.input.json equals the committed
//         proof's disclosureHash public signal (disburse pub[2] — the on-chain
//         value ingest.ts hands verifyDisclosure as `expected`)
//   p3    parseEnvelope snapshots: the committed disburse256 authority tail
//         (arbiter key = the fixture AUTHORITY scalar) + one deterministic
//         synthetic envelope per op kind, pinning the decrypt + slice result.
//
// This final form runs every pin against @bongtu/core/envelope — the module
// that now owns the codec — so any layout/chain drift from the recorded bytes
// fails here, in the fast sdk suite, not at the anvil gate.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  deriveKeypair,
  commitment,
  poseidonEncrypt,
  ecdhSharedSecret,
} from "../src/note.js";
import type { Point } from "../src/babyjub.js";

import {
  parseEnvelope,
  buildAuthorityPlaintext,
  envelopePlaintextLen,
  authorityCiphertextLen,
  disclosureChain,
  type OpKind,
  type ParsedEnvelope,
} from "../src/envelope.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const FIXTURES = join(ROOT, "contracts", "test", "fixtures");

// ---- pin plumbing -----------------------------------------------------------

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");
/** Canonical bytes of a field-element list: sha256 of the decimal-string JSON. */
const shaElts = (xs: bigint[]): string => sha256(JSON.stringify(xs.map((x) => x.toString())));
/** Canonical bytes of a parsed envelope (bigints as decimal strings). */
const shaParsed = (p: ParsedEnvelope): string =>
  sha256(JSON.stringify(p, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v)));

function pin(name: string, actual: string): void {
  assert.equal(actual, PINS[name], `byte-pin ${name} diverged`);
}

// Recorded at main 875c179 against the pre-consolidation copies (U-N1 phase 1).
const PINS: Record<string, string> = {
  "p1.A.plain": "f45ab13d756db7ec1194d88677759949c82bc846ea3c2cde631a94370f1cc388",
  "p1.A.ct": "6a967498e139ed952a4632a9f366c1c6ef0a9a1cdbbadb828d15d7dbcf9ff2a8",
  "p1.A.dh": "10410754105375865441329948274228936976154835740787208180438963577568607987646",
  "p1.B.plain": "d374c99999acd980fb7aac3bfe49c85097850c4d6b26d08bfb93d95f9425f495",
  "p1.B.ct": "b7dc4312a150ada0fa52cf5cff3e5baaa44c989e29ff7b6b14c6e9cba4f13735",
  "p1.C.plain": "b0d7f48c4448b1f38354c2c125ab9a13e5841add944cd87eab3b8945c0e58c7e",
  "p1.C.ct": "18aecfa877ef988f74097ea97e5f7aa30a97abeccd8eaea5e8000f725d3d602a",
  "p1.D.honest.plain": "d374c99999acd980fb7aac3bfe49c85097850c4d6b26d08bfb93d95f9425f495", // == p1.B by construction
  "p1.D.d3.plain": "56af95af5410016a48c689e63da0044d4c6c552f2f2f64efab31c7b8d35b81b7",
  "p1.D.d3.ct": "f95363ef8851a456a4f874fe08f1829772895be84891127b05271890f5f5a5c2",
  "p2.ct": "4dc51ba09d8064fa53701142520d65ba49d90c83af4e5215159086e0c4a6678a",
  "p3.disburse256": "d886e4ac7447cf933c999729e5e73aa80abb2f64ea338cc4342de31c45b392a6",
  "p3.deposit": "3af9037204d708c178633c2f23345d9d17b33427c5eb912adbb8118bb853146a",
  "p3.withdraw": "949f55c40e7cefdf7aab88f13d69143dd85ca5c12edf12d518f591f389847ace",
  "p3.transfer": "14fbd40affe42c14051a3815a84e3ac9b6c71de8fab89df20f51277c1e58e167",
};

// ---- shared fixture actors --------------------------------------------------

const AUTHORITY = deriveKeypair(555555555555555555555555n); // the ONE fixture arbiter key

// =============================================================================
// p1.A — the admin-web disburse assembly material (assemble.test.ts fixture(3))
// =============================================================================

test("p1.A: sdk builder reproduces the admin buildDisburseRequest envelope bytes", () => {
  const B = 256;
  const employer = deriveKeypair(313131313131313131313131n);
  const value = 100000n;
  const inSalt = 777n;
  const ARBITER_PUB: Point = [
    3913862942419584217034784582196041949017644467033355253711012199317627839810n,
    9603702957807229873011073182281683387900303214140383090738501285426490726765n,
  ]; // deploy/addresses.91342.json arbiterKeyX/Y (== admin config DEFAULTS.arbiterPubKey)
  const ecdh = 900000000000000000007n;
  const nonce = 424242424243n;

  // The site's output layout: 3 recipients, then the change note, then
  // zero-value pads to B (padSeed derivation), salts = saltSeed + i.
  const outs: { owner: Point; value: bigint }[] = [];
  for (let i = 0; i < 3; i++) {
    outs.push({ owner: deriveKeypair(4000000019n + BigInt(i) * 1000003n).publicKey, value: 100n + BigInt(i) });
  }
  const disbursed = outs.reduce((a, o) => a + o.value, 0n);
  outs.push({ owner: employer.publicKey, value: value - disbursed }); // change
  for (let i = outs.length; i < B; i++) {
    outs.push({ owner: deriveKeypair(50000000000n + BigInt(i) * 1000003n + 1n).publicKey, value: 0n });
  }
  const outputSalts = outs.map((_, i) => 9000000n + BigInt(i));

  const plain = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: employer.publicKey, value, salt: inSalt }],
    outputs: outs.map((o, i) => ({ owner: o.owner, value: o.value, salt: outputSalts[i] })),
  });
  pin("p1.A.plain", shaElts(plain));

  // Full wire bytes: receiver run ++ authority tail, and the chain over them.
  const receiverFlat = outs.flatMap((o, i) =>
    poseidonEncrypt([o.value, outputSalts[i]], ecdhSharedSecret(ecdh, o.owner), nonce),
  );
  const authorityCt = poseidonEncrypt(plain, ecdhSharedSecret(ecdh, ARBITER_PUB), nonce);
  const full = [...receiverFlat, ...authorityCt];
  assert.equal(full.length, 2054);
  pin("p1.A.ct", shaElts(full));
  pin("p1.A.dh", disclosureChain(full).toString());
});

// =============================================================================
// p1.B — the e2e_orchestrator disburse material (B=16)
// =============================================================================

test("p1.B: sdk builder reproduces the e2e_orchestrator envelope bytes", () => {
  const B = 16;
  const EMPLOYER = deriveKeypair(111111111111111111111111n);
  const RCPTS = Array.from({ length: B }, (_, i) => deriveKeypair(2000000011n + BigInt(i) * 1000003n));
  const amounts = Array.from({ length: B }, (_, i) => 100n + BigInt(i) * 3n);
  const V = amounts.reduce((a, x) => a + x, 0n);
  const sD0 = 5000001n;
  const sR = (i: number): bigint => 6000000n + BigInt(i);

  const authPlain = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: EMPLOYER.publicKey, value: V, salt: sD0 }],
    outputs: amounts.map((v, i) => ({ owner: RCPTS[i].publicKey, value: v, salt: sR(i) })),
  });
  assert.equal(authPlain.length, envelopePlaintextLen("disburse", B));
  pin("p1.B.plain", shaElts(authPlain));

  const authCt = poseidonEncrypt(
    authPlain,
    ecdhSharedSecret(700000000000000000001n, AUTHORITY.publicKey), // ECDH_DISBURSE
    111111111111n, // NONCE_DISBURSE
  );
  pin("p1.B.ct", shaElts(authCt));
});

// =============================================================================
// p1.C — the giwa_disburse256 material (B=256, live arbiter key)
// =============================================================================

test("p1.C: sdk builder reproduces the giwa_disburse256 envelope bytes", () => {
  const B = 256;
  const addr = JSON.parse(readFileSync(join(ROOT, "deploy", "addresses.91342.json"), "utf8")) as {
    arbiterKeyX: string;
    arbiterKeyY: string;
  };
  const ARBITER: Point = [BigInt(addr.arbiterKeyX), BigInt(addr.arbiterKeyY)];
  const EMPLOYER = deriveKeypair(313131313131313131313131n);
  const RCPTS = Array.from({ length: B }, (_, i) => deriveKeypair(4000000019n + BigInt(i) * 1000003n));
  const amounts = Array.from({ length: B }, (_, i) => 100n + BigInt(i));
  const V = amounts.reduce((a, x) => a + x, 0n);
  const sD0 = 8000001n;
  const sR = (i: number): bigint => 9000000n + BigInt(i);

  const authPlain = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: EMPLOYER.publicKey, value: V, salt: sD0 }],
    outputs: amounts.map((v, i) => ({ owner: RCPTS[i].publicKey, value: v, salt: sR(i) })),
  });
  assert.equal(authPlain.length, envelopePlaintextLen("disburse", B));
  pin("p1.C.plain", shaElts(authPlain));

  const authCt = poseidonEncrypt(authPlain, ecdhSharedSecret(900000000000000000007n, ARBITER), 424242424243n);
  pin("p1.C.ct", shaElts(authCt));
});

// =============================================================================
// p1.D — the scenario.ts material (honest + authority-tampered-leg input shape)
// =============================================================================

test("p1.D: sdk builder reproduces the scenario authorityPlain bytes (both leg shapes)", () => {
  const B = 16;
  const EMPLOYER = deriveKeypair(111111111111111111111111n);
  const RCPTS = Array.from({ length: B }, (_, i) => deriveKeypair(2000000011n + BigInt(i) * 1000003n));
  const amounts = Array.from({ length: B }, (_, i) => 100n + BigInt(i) * 3n);
  const V = amounts.reduce((a, x) => a + x, 0n);
  const sD0 = 5000001n;
  const sR = (i: number): bigint => 6000000n + BigInt(i);
  const sR3 = (i: number): bigint => 6200000n + BigInt(i);
  const sRes = 7200001n;

  // honest disburse leg (same material as p1.B by construction)
  const honest = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: EMPLOYER.publicKey, value: V, salt: sD0 }],
    outputs: amounts.map((v, i) => ({ owner: RCPTS[i].publicKey, value: v, salt: sR(i) })),
  });
  pin("p1.D.honest.plain", shaElts(honest));

  // disburse#3 leg: DISTINCT input shape (recipient0-owned zero-value residue note)
  const d3 = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: RCPTS[0].publicKey, value: 0n, salt: sRes }],
    outputs: RCPTS.map((r, i) => ({ owner: r.publicKey, value: 0n, salt: sR3(i) })),
  });
  pin("p1.D.d3.plain", shaElts(d3));
  const authCt3 = poseidonEncrypt(
    d3,
    ecdhSharedSecret(970000000000000000011n, AUTHORITY.publicKey), // ECDH_D3
    777777777777n, // NONCE_D3
  );
  pin("p1.D.d3.ct", shaElts(authCt3));
});

// =============================================================================
// p2 — the CIRCUIT ground truth: disclosure chain over the ciphertext derived
// from the committed disburse256 input fixture == the committed proof's
// disclosureHash public signal (disburse pub[2])
// =============================================================================

interface Disburse256Fixture {
  inputValues: string[];
  inputSalts: string[];
  inputOwnerPrivateKey: string;
  ecdhPrivateKey: string;
  encryptionNonce: string;
  outputValues: string[];
  outputSalts: string[];
  outputOwnerPublicKeys: [string, string][];
  authorityPublicKey: [string, string];
}

function committedDisburse256(): {
  input: Disburse256Fixture;
  pub: string[];
  receiverFlat: bigint[];
  authorityCt: bigint[];
} {
  const input = JSON.parse(
    readFileSync(join(FIXTURES, "disburse256.input.json"), "utf8"),
  ) as Disburse256Fixture;
  const pub = JSON.parse(readFileSync(join(FIXTURES, "disburse256.public.json"), "utf8")) as string[];

  const ecdh = BigInt(input.ecdhPrivateKey);
  const nonce = BigInt(input.encryptionNonce);
  const owners: Point[] = input.outputOwnerPublicKeys.map((p) => [BigInt(p[0]), BigInt(p[1])]);
  const receiverFlat = owners.flatMap((owner, i) =>
    poseidonEncrypt([BigInt(input.outputValues[i]), BigInt(input.outputSalts[i])], ecdhSharedSecret(ecdh, owner), nonce),
  );
  const inOwner = deriveKeypair(BigInt(input.inputOwnerPrivateKey)).publicKey;
  const authPlain = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: inOwner, value: BigInt(input.inputValues[0]), salt: BigInt(input.inputSalts[0]) }],
    outputs: owners.map((owner, i) => ({
      owner,
      value: BigInt(input.outputValues[i]),
      salt: BigInt(input.outputSalts[i]),
    })),
  });
  const authorityCt = poseidonEncrypt(
    authPlain,
    ecdhSharedSecret(ecdh, [BigInt(input.authorityPublicKey[0]), BigInt(input.authorityPublicKey[1])]),
    nonce,
  );
  return { input, pub, receiverFlat, authorityCt };
}

test("p2: disclosureChain(committed disburse256 ciphertext) == committed proof pub[2]", () => {
  const { pub, receiverFlat, authorityCt } = committedDisburse256();
  const full = [...receiverFlat, ...authorityCt];
  assert.equal(full.length, 2054, "receiver(1024) ++ authority(1030) == disburseCiphertextLen(256)");
  assert.equal(full.length, 4 * 256 + authorityCiphertextLen("disburse", 256));
  // The fold the indexer verifies (disclosure.ts) over the emitted elements must
  // equal the disclosureHash the circuit committed to — pub[2] of the disburse
  // public-signal layout ([0,1]=ecdhPub, [2]=disclosureHash, [3]=subtreeRoot).
  assert.equal(disclosureChain(full), BigInt(pub[2]), "TS chain != in-circuit disclosureHash");
  pin("p2.ct", shaElts(full));
});

// =============================================================================
// p3 — parseEnvelope snapshots (decrypt + slice result)
// =============================================================================

test("p3: parseEnvelope on the committed disburse256 authority tail (arbiter key)", () => {
  const { input, pub, authorityCt } = committedDisburse256();
  // The fixture arbiter key IS the shared AUTHORITY constant (Deploy.s.sol default).
  assert.deepEqual(
    [AUTHORITY.publicKey[0], AUTHORITY.publicKey[1]],
    [BigInt(input.authorityPublicKey[0]), BigInt(input.authorityPublicKey[1])],
    "fixture authorityPublicKey != deriveKeypair(555...555)",
  );
  const parsed = parseEnvelope(
    AUTHORITY.formattedPrivateKey,
    [BigInt(pub[0]), BigInt(pub[1])], // chain-carried ecdhPublicKey
    BigInt(input.encryptionNonce),
    authorityCt,
    "disburse",
    256,
  );
  assert.equal(parsed.inputs.length, 1);
  assert.equal(parsed.outputs.length, 256);
  assert.equal(parsed.inputs[0].value, 25600n); // sum(100+i, i<256)
  const inOwner = deriveKeypair(BigInt(input.inputOwnerPrivateKey)).publicKey;
  assert.deepEqual(parsed.inputs[0].owner, [inOwner[0], inOwner[1]]);
  // every recovered output rebuilds its committed commitment
  parsed.outputs.forEach((o, i) => {
    assert.equal(
      commitment(o.value, o.salt, o.owner),
      commitment(BigInt(input.outputValues[i]), BigInt(input.outputSalts[i]), [
        BigInt(input.outputOwnerPublicKeys[i][0]),
        BigInt(input.outputOwnerPublicKeys[i][1]),
      ]),
      `output ${i} commitment mismatch`,
    );
  });
  pin("p3.disburse256", shaParsed(parsed));
});

test("p3: parseEnvelope slice snapshots per op kind (synthetic deterministic envelopes)", () => {
  const B = 16;
  const o = (s: bigint): Point => deriveKeypair(s).publicKey;
  const ecdhPriv = 77777777777777777n;
  const ecdhPub = deriveKeypair(ecdhPriv).publicKey;
  const nonce = 999999999999n;
  const enc = (plain: bigint[]): bigint[] =>
    poseidonEncrypt(plain, ecdhSharedSecret(ecdhPriv, AUTHORITY.publicKey), nonce);
  const parse = (kind: "deposit" | "withdraw" | "transfer", plain: bigint[]): ParsedEnvelope =>
    parseEnvelope(AUTHORITY.formattedPrivateKey, ecdhPub, nonce, enc(plain), kind, B);

  // deposit: [o0.x,o0.y, o1.x,o1.y, v0,s0, v1,s1] — sentinel values per slot
  const d = parse("deposit", [...o(1001n), ...o(1002n), 11n, 12n, 21n, 22n]);
  assert.equal(d.inputs.length, 0);
  assert.deepEqual(
    d.outputs.map((x) => [x.value, x.salt]),
    [[11n, 12n], [21n, 22n]],
  );
  pin("p3.deposit", shaParsed(d));

  // withdraw: [inOwn.x,inOwn.y, iv0,is0, iv1,is1, ch.x,ch.y, cv,cs]
  const w = parse("withdraw", [...o(2001n), 31n, 32n, 41n, 42n, ...o(2002n), 51n, 52n]);
  assert.equal(w.inputs.length, 2);
  assert.deepEqual(w.inputs[0].owner, w.inputs[1].owner); // ONE shared input owner
  assert.deepEqual(w.outputs.map((x) => [x.value, x.salt]), [[51n, 52n]]);
  pin("p3.withdraw", shaParsed(w));

  // transfer: [inOwn.x,inOwn.y, iv0,is0, iv1,is1, o0.x,o0.y, o1.x,o1.y, ov0,os0, ov1,os1]
  const t = parse("transfer", [
    ...o(3001n), 61n, 62n, 71n, 72n, ...o(3002n), ...o(3003n), 81n, 82n, 91n, 92n,
  ]);
  assert.equal(t.inputs.length, 2);
  assert.deepEqual(
    t.outputs.map((x) => [x.value, x.salt]),
    [[81n, 82n], [91n, 92n]],
  );
  pin("p3.transfer", shaParsed(t));
});

// =============================================================================
// round-trips: buildAuthorityPlaintext -> poseidonEncrypt -> parseEnvelope
// recovers the original fields, for every op kind
// =============================================================================

function envFor(kind: OpKind, B: number): ParsedEnvelope {
  const kp = (s: bigint): [bigint, bigint] => deriveKeypair(s).publicKey;
  const sender = kp(880001n);
  switch (kind) {
    case "deposit":
      return {
        inputs: [],
        outputs: [
          { owner: kp(880002n), value: 1234n, salt: 660001n },
          { owner: kp(880003n), value: 0n, salt: 660002n },
        ],
      };
    case "withdraw":
      return {
        inputs: [
          { owner: sender, value: 600n, salt: 660003n },
          { owner: sender, value: 0n, salt: 660004n }, // padded input carries value 0 (§5.2 belt)
        ],
        outputs: [{ owner: kp(880004n), value: 100n, salt: 660005n }],
      };
    case "transfer":
      return {
        inputs: [
          { owner: sender, value: 500n, salt: 660006n },
          { owner: sender, value: 0n, salt: 660007n },
        ],
        outputs: [
          { owner: kp(880005n), value: 60n, salt: 660008n },
          { owner: kp(880006n), value: 440n, salt: 660009n },
        ],
      };
    case "disburse":
      return {
        inputs: [{ owner: sender, value: 4950n, salt: 660010n }],
        outputs: Array.from({ length: B }, (_, i) => ({
          owner: kp(990000n + BigInt(i)),
          value: BigInt(i) * 10n,
          salt: 770000n + BigInt(i),
        })),
      };
  }
}

test("round-trip: build -> encrypt -> parse == original fields (all four kinds)", () => {
  const B = 16;
  const ecdhPriv = 313373133731337n;
  const ecdhPub = deriveKeypair(ecdhPriv).publicKey;
  const nonce = 121212121212n;
  for (const kind of ["deposit", "withdraw", "transfer", "disburse"] as OpKind[]) {
    const env = envFor(kind, B);
    const plain = buildAuthorityPlaintext(kind, env);
    assert.equal(plain.length, envelopePlaintextLen(kind, B), `${kind} plaintext length`);
    const ct = poseidonEncrypt(plain, ecdhSharedSecret(ecdhPriv, AUTHORITY.publicKey), nonce);
    assert.equal(ct.length, authorityCiphertextLen(kind, B), `${kind} ciphertext length`);
    const parsed = parseEnvelope(AUTHORITY.formattedPrivateKey, ecdhPub, nonce, ct, kind, B);
    assert.deepEqual(parsed, env, `${kind} round-trip`);
  }
});

test("authority-tail tamper: an early flip garbles recovery; the final element is caught only by the disclosureChain", () => {
  const B = 16;
  const ecdhPriv = 424242424242421n;
  const ecdhPub = deriveKeypair(ecdhPriv).publicKey;
  const nonce = 343434343434n;
  const env = envFor("disburse", B);
  const trueCommits = env.outputs.map((o) => commitment(o.value, o.salt, o.owner));

  const ct = poseidonEncrypt(
    buildAuthorityPlaintext("disburse", env),
    ecdhSharedSecret(ecdhPriv, AUTHORITY.publicKey),
    nonce,
  );
  // Flip the FIRST authority element (the scenario's disburse#3 attack). The
  // sponge reseeds from the ciphertext itself, so recovery goes wrong from that
  // chunk on — the arbiter's commitment cross-check (ledger.ts) MUST see a
  // mismatch; poseidonDecrypt has no integrity tag, so garbling, not throwing,
  // is the detection contract.
  const tampered = [...ct];
  tampered[0] = tampered[0] + 1n;
  const parsed = parseEnvelope(AUTHORITY.formattedPrivateKey, ecdhPub, nonce, tampered, "disburse", B);
  const recovered = parsed.outputs.map((o) => commitment(o.value, o.salt, o.owner));
  assert.notDeepEqual(recovered, trueCommits, "tampered tail must not reproduce the true commitments");
  assert.notDeepEqual(parsed, env, "tampered tail must not round-trip to the original fields");

  // Blind spot made explicit: poseidonDecrypt reads floor(len/3) chunks and
  // never touches the FINAL squeeze element, so flipping it leaves recovery
  // byte-identical — the ledger cross-check cannot see it. The disclosureChain
  // (checked against the proof's disclosureHash public) is what catches it.
  const lastFlipped = [...ct];
  lastFlipped[lastFlipped.length - 1] = lastFlipped[lastFlipped.length - 1] + 1n;
  const parsedLast = parseEnvelope(AUTHORITY.formattedPrivateKey, ecdhPub, nonce, lastFlipped, "disburse", B);
  assert.deepEqual(parsedLast, env, "final-element flip is invisible to decryption by construction");
  assert.notEqual(
    disclosureChain(lastFlipped),
    disclosureChain(ct),
    "the disclosureChain must diverge on a final-element flip — it is the only detector",
  );
});

test("builder rejects shapes no circuit produces", () => {
  const env = envFor("transfer", 16);
  // wrong counts
  assert.throws(() => buildAuthorityPlaintext("deposit", env), /deposit consumes no inputs/);
  assert.throws(
    () => buildAuthorityPlaintext("withdraw", { inputs: env.inputs, outputs: env.outputs }),
    /exactly 1 change output/,
  );
  assert.throws(
    () => buildAuthorityPlaintext("disburse", { inputs: env.inputs, outputs: env.outputs }),
    /exactly 1 input/,
  );
  // transfer/withdraw inputs must share ONE owner (single inputOwnerPrivateKey)
  const twoOwners: ParsedEnvelope = {
    inputs: [
      { owner: deriveKeypair(880001n).publicKey, value: 1n, salt: 2n },
      { owner: deriveKeypair(880002n).publicKey, value: 3n, salt: 4n },
    ],
    outputs: env.outputs,
  };
  assert.throws(() => buildAuthorityPlaintext("transfer", twoOwners), /share ONE owner/);
});
