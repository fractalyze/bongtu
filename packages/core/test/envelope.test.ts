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
//   p1.A  apps/payroll-web/src/lib/disburse.ts   (assemble.test.ts fixture(3), B=256;
//                                               recorded from the GENUINE function
//                                               output — decrypted ciphertext tail)
//   p1.B  deploy/gates/e2e_orchestrator.ts           (its inline actor material, B=16)
//   p1.C  the live 256-disburse run            (its inline actor material +
//                                               the deploy record's arbiter, B=256)
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

import { CHAIN_ID } from "@bongtu/core/network";
import {
  deriveKeypair,
  commitment,
  poseidonEncrypt,
  poseidonDecrypt,
  ecdhSharedSecret,
} from "@bongtu/core/note";
import type { Point } from "@bongtu/core/babyjub";

import {
  parseEnvelope,
  buildAuthorityPlaintext,
  envelopePlaintextLen,
  authorityCiphertextLen,
  disclosureChain,
  type OpKind,
  type ParsedEnvelope,
} from "@bongtu/core/envelope";
import {
  KEM_SECRET_KEY_BYTES,
  hybridEnvelopeKey,
  kemPkFromSecret,
  kemSsToLimbs,
  ml_kem768,
} from "@bongtu/core/kem";
// THE fixture arbiter's bjj scalar, declared once for the whole repo.
import { FIXTURE_ARBITER_SCALAR } from "../../../circuits/fixtures/fixture_lib.js";

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
  // p2.ct / p3.disburse256 RE-RECORDED for U-P1 (pq hybrid envelope): the
  // committed disburse256 fixture was re-proven with the hybrid
  // (ECDH||ML-KEM-768) envelope key and deterministic single-leaf input, so the
  // fixture-derived bytes legitimately changed (the ground-truth assert
  // disclosureChain == pub[2] is re-proven against the NEW committed proof).
  "p2.ct": "56150258c69fe5343080f01bac5558ce00480dc2afab0922e4eb18adad5c6de1",
  "p3.disburse256": "5d69493d2beec596c5bd35c70ddbb1a17cb3154802b8981c7ca5bf9d7721b130",
  "p3.deposit": "3af9037204d708c178633c2f23345d9d17b33427c5eb912adbb8118bb853146a",
  "p3.withdraw": "949f55c40e7cefdf7aab88f13d69143dd85ca5c12edf12d518f591f389847ace",
  "p3.transfer": "14fbd40affe42c14051a3815a84e3ac9b6c71de8fab89df20f51277c1e58e167",
};

// ---- shared fixture actors --------------------------------------------------

const AUTHORITY = deriveKeypair(FIXTURE_ARBITER_SCALAR); // the ONE fixture arbiter key

// The fixture arbiter ML-KEM keypair + the disburse256 fixture encapsulation
// (label-derived randomness), mirroring circuits/fixtures/fixture_lib.ts — the committed
// disburse256 proof's authority tail is encrypted under the HYBRID key
// (pq-envelope-design.md §2), so the p2/p3 ground-truth recompute needs the
// same kemSs limbs the witness carried.
const shaBytes = (label: string): Uint8Array => new Uint8Array(createHash("sha256").update(label).digest());
const FIXTURE_KEM = ml_kem768.keygen(
  new Uint8Array([...shaBytes("bongtu/fixture/kem/seed/d"), ...shaBytes("bongtu/fixture/kem/seed/z")]),
);
const DISBURSE256_KEM_SS = kemSsToLimbs(
  ml_kem768.encapsulate(FIXTURE_KEM.publicKey, shaBytes("bongtu/fixture/kem/encap/disburse256")).sharedSecret,
);

// =============================================================================
// p1.A — the payroll-web disburse assembly material (assemble.test.ts fixture(3))
// =============================================================================

test("p1.A: sdk builder reproduces the admin buildDisburseRequest envelope bytes", () => {
  const B = 256;
  const employer = deriveKeypair(313131313131313131313131n);
  const value = 100000n;
  const inSalt = 777n;
  const ARBITER_PUB: Point = [
    3913862942419584217034784582196041949017644467033355253711012199317627839810n,
    9603702957807229873011073182281683387900303214140383090738501285426490726765n,
  ]; // the deploy record's arbiterKeyX/Y (== admin config DEFAULTS.arbiterPubKey)
  const ecdh = 900000000000000000007n;
  const nonce = 424242424243n;

  // The site's output layout: 3 recipients, then the change note, then
  // zero-value pads to B (padSeed derivation), salts = saltSeed + i.
  const outs: { owner: Point; value: bigint }[] = [];
  for (const i of Array(3).keys()) {
    outs.push({ owner: deriveKeypair(4000000019n + BigInt(i) * 1000003n).publicKey, value: 100n + BigInt(i) });
  }
  const disbursed = outs.reduce((a, o) => a + o.value, 0n);
  outs.push({ owner: employer.publicKey, value: value - disbursed }); // change
  for (const i of Array.from({ length: B - outs.length }, (_, j) => j + outs.length)) {
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
// p1.C — the live 256-disburse material (B=256, live arbiter key)
// =============================================================================

test("p1.C: sdk builder reproduces the live 256-disburse envelope bytes", () => {
  const B = 256;
  // The arbiter did NOT rotate when the deployment moved chains, so the recorded
  // bytes stay valid read from the CURRENT record — a rotation would not.
  const addr = JSON.parse(readFileSync(join(ROOT, "deploy", `addresses.${CHAIN_ID}.json`), "utf8")) as {
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
    hybridEnvelopeKey(
      ecdhSharedSecret(ecdh, [BigInt(input.authorityPublicKey[0]), BigInt(input.authorityPublicKey[1])]),
      DISBURSE256_KEM_SS,
    ),
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
    DISBURSE256_KEM_SS, // arbiter-decapsulated limbs -> hybrid key
  );
  assert.equal(parsed.inputs.length, 1);
  assert.equal(parsed.outputs.length, 256);
  assert.equal(parsed.inputs[0].value, 58240n); // sum(100+i, i<256) over the U-P1 fixture amounts
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
    case "transfer10":
      // Every output to ONE owner (the self-merge): duplicates are legal at this
      // arity (§11-8 v1.1 per-output nonce) and the codec must carry them.
      return {
        inputs: Array.from({ length: 10 }, (_, i) => ({
          owner: sender,
          value: BigInt(i) * 100n,
          salt: 661000n + BigInt(i),
        })),
        outputs: Array.from({ length: 10 }, (_, i) => ({
          owner: sender,
          value: i === 0 ? 4500n : 0n,
          salt: 662000n + BigInt(i),
        })),
      };
    case "transfer10x2":
      // The merge shape: ten spent notes folded into output 0, a zero change
      // note at output 1, both outputs the sender's own key.
      return {
        inputs: Array.from({ length: 10 }, (_, i) => ({
          owner: sender,
          value: BigInt(i) * 100n,
          salt: 663000n + BigInt(i),
        })),
        outputs: [
          { owner: sender, value: 4500n, salt: 664000n },
          { owner: sender, value: 0n, salt: 664001n },
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

test("round-trip: build -> encrypt -> parse == original fields (every op kind)", () => {
  const B = 16;
  const ecdhPriv = 313373133731337n;
  const ecdhPub = deriveKeypair(ecdhPriv).publicKey;
  const nonce = 121212121212n;
  for (const kind of [
    "deposit",
    "withdraw",
    "transfer",
    "transfer10",
    "transfer10x2",
    "disburse",
  ] as OpKind[]) {
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

// =============================================================================
// transfer10 (10-in / 10-out): the arity-10 instantiation of the transfer base
// =============================================================================

test("transfer10 envelope sizes: 62 plaintext fields -> 64 ciphertext elements", () => {
  // The circuit publishes cipherTextAuthority[64]; the plaintext is
  // 2 (shared input owner) + 2*10 (input value,salt) + 4*10 (output owner,value,salt).
  assert.equal(envelopePlaintextLen("transfer10", 0), 62);
  assert.equal(envelopePlaintextLen("transfer10", 0), 2 + 2 * 10 + 4 * 10);
  assert.equal(authorityCiphertextLen("transfer10", 0), 64);
  // B is a disburse-only parameter: transfer10's arity is fixed by the circuit.
  assert.equal(envelopePlaintextLen("transfer10", 256), 62);
});

test("transfer10 layout: the field order the circuit encrypts, at arity 10", () => {
  const kp = (s: bigint): Point => deriveKeypair(s).publicKey;
  const sender = kp(551001n);
  const env: ParsedEnvelope = {
    inputs: Array.from({ length: 10 }, (_, i) => ({
      owner: sender,
      value: 10n + BigInt(i),
      salt: 100n + BigInt(i),
    })),
    outputs: Array.from({ length: 10 }, (_, i) => ({
      owner: kp(552000n + BigInt(i)),
      value: 200n + BigInt(i),
      salt: 300n + BigInt(i),
    })),
  };
  const p = buildAuthorityPlaintext("transfer10", env);
  assert.equal(p.length, 62);
  assert.deepEqual([p[0], p[1]], sender, "fields 0..1 are the shared input owner");
  for (const i of Array(10).keys()) {
    assert.equal(p[2 + 2 * i], env.inputs[i].value, `input ${i} value at ${2 + 2 * i}`);
    assert.equal(p[3 + 2 * i], env.inputs[i].salt, `input ${i} salt at ${3 + 2 * i}`);
    assert.equal(p[22 + 2 * i], env.outputs[i].owner[0], `output ${i} owner.x at ${22 + 2 * i}`);
    assert.equal(p[23 + 2 * i], env.outputs[i].owner[1], `output ${i} owner.y at ${23 + 2 * i}`);
    assert.equal(p[42 + 2 * i], env.outputs[i].value, `output ${i} value at ${42 + 2 * i}`);
    assert.equal(p[43 + 2 * i], env.outputs[i].salt, `output ${i} salt at ${43 + 2 * i}`);
  }
});

test("transfer10 builder rejects wrong arity and a mismatched input owner in ANY slot", () => {
  const full = envFor("transfer10", 0);
  assert.throws(
    () => buildAuthorityPlaintext("transfer10", { inputs: full.inputs, outputs: full.outputs.slice(0, 9) }),
    /exactly 10 outputs/,
  );
  assert.throws(
    () => buildAuthorityPlaintext("transfer10", { inputs: full.inputs.slice(0, 4), outputs: full.outputs }),
    /exactly 10 inputs/,
  );
  // The shared-owner check must cover every slot, not just the first two: one
  // circuit inputOwnerPrivateKey means input 7 cannot belong to someone else.
  const oddSlot: ParsedEnvelope = {
    inputs: full.inputs.map((n, i) =>
      i === 7 ? { ...n, owner: deriveKeypair(553007n).publicKey } : n,
    ),
    outputs: full.outputs,
  };
  assert.throws(() => buildAuthorityPlaintext("transfer10", oddSlot), /share ONE owner/);
});

test("transfer10 fixture parity: the committed witness input agrees with the sdk", () => {
  // circuits/fixtures/inputs/transfer10.json is what the committed proof was generated
  // from, so the codec and the note primitives must agree with it field for field.
  const inp = JSON.parse(
    readFileSync(join(ROOT, "circuits", "fixtures", "inputs", "transfer10.json"), "utf8"),
  ) as Record<string, string[] | string[][] | string>;
  const arr = (k: string): bigint[] => (inp[k] as string[]).map(BigInt);
  const owners = (inp.outputOwnerPublicKeys as unknown as string[][]).map(
    (p) => [BigInt(p[0]), BigInt(p[1])] as Point,
  );

  const inValues = arr("inputValues");
  const outValues = arr("outputValues");
  const outSalts = arr("outputSalts");
  const enabled = arr("enabled");
  assert.equal(inValues.length, 10);
  assert.equal(outValues.length, 10);

  // commitment equality: recomputing every output commitment with the sdk
  // reproduces the witness input the circuit hashed.
  const outCommits = arr("outputCommitments");
  for (const i of Array(10).keys()) {
    assert.equal(commitment(outValues[i], outSalts[i], owners[i]), outCommits[i], `output ${i}`);
  }
  // conservation: CheckSum is an equality over ALL 10 slots, pads included.
  assert.equal(
    inValues.reduce((a, v) => a + v, 0n),
    outValues.reduce((a, v) => a + v, 0n),
  );
  // the §5.2 value belt on the fixture's own padding: enabled=0 ⟹ value=0.
  for (const i of Array(10).keys()) {
    if (enabled[i] === 0n) assert.equal(inValues[i], 0n, `padded slot ${i} must carry value 0`);
  }

  // The envelope over this fixture is the 62-field layout, and it round-trips.
  const inOwner = deriveKeypair(BigInt(inp.inputOwnerPrivateKey as string)).publicKey;
  const inSalts = arr("inputSalts");
  const env: ParsedEnvelope = {
    inputs: inValues.map((v, i) => ({ owner: inOwner, value: v, salt: inSalts[i] })),
    outputs: outValues.map((v, i) => ({ owner: owners[i], value: v, salt: outSalts[i] })),
  };
  const plain = buildAuthorityPlaintext("transfer10", env);
  assert.equal(plain.length, envelopePlaintextLen("transfer10", 0));
  const ecdhPriv = 616161616161616n;
  const nonce = BigInt(inp.encryptionNonce as string);
  const ct = poseidonEncrypt(plain, ecdhSharedSecret(ecdhPriv, AUTHORITY.publicKey), nonce);
  assert.equal(ct.length, authorityCiphertextLen("transfer10", 0));
  const parsed = parseEnvelope(
    AUTHORITY.formattedPrivateKey,
    deriveKeypair(ecdhPriv).publicKey,
    nonce,
    ct,
    "transfer10",
    0,
  );
  assert.deepEqual(parsed, env);
});

// =============================================================================
// transfer10x2 (10-in / 2-out): the same base at ten inputs but two outputs
// =============================================================================

test("transfer10x2 envelope sizes: 30 plaintext fields -> 31 ciphertext elements", () => {
  // The circuit publishes cipherTextAuthority[31]; the plaintext is
  // 2 (shared input owner) + 2*10 (input value,salt) + 4*2 (output owner,value,salt).
  assert.equal(envelopePlaintextLen("transfer10x2", 0), 30);
  assert.equal(envelopePlaintextLen("transfer10x2", 0), 2 + 2 * 10 + 4 * 2);
  // 30 is already a multiple of 3, so the sponge pads by nothing and the run is
  // plaintext + the single final squeeze — the one arity where padding is zero.
  assert.equal(authorityCiphertextLen("transfer10x2", 0), 31);
  // B is a disburse-only parameter: transfer10x2's arity is fixed by the circuit.
  assert.equal(envelopePlaintextLen("transfer10x2", 256), 30);
  // Half of transfer10's envelope for the same ten spent notes: what the eight
  // dropped output slots cost in disclosure as well as in gas.
  assert.equal(envelopePlaintextLen("transfer10", 0) - envelopePlaintextLen("transfer10x2", 0), 32);
});

test("transfer10x2 layout: the field order the circuit encrypts, at (10, 2)", () => {
  const kp = (s: bigint): Point => deriveKeypair(s).publicKey;
  const sender = kp(555001n);
  const env: ParsedEnvelope = {
    inputs: Array.from({ length: 10 }, (_, i) => ({
      owner: sender,
      value: 10n + BigInt(i),
      salt: 100n + BigInt(i),
    })),
    outputs: [
      { owner: kp(556001n), value: 200n, salt: 300n }, // payment
      { owner: sender, value: 201n, salt: 301n }, // change
    ],
  };
  const p = buildAuthorityPlaintext("transfer10x2", env);
  assert.equal(p.length, 30);
  assert.deepEqual([p[0], p[1]], sender, "fields 0..1 are the shared input owner");
  for (const i of Array(10).keys()) {
    assert.equal(p[2 + 2 * i], env.inputs[i].value, `input ${i} value at ${2 + 2 * i}`);
    assert.equal(p[3 + 2 * i], env.inputs[i].salt, `input ${i} salt at ${3 + 2 * i}`);
  }
  // The output run starts right after the ten input pairs — at 22, not at 42
  // where transfer10 puts it. A layout that hardcoded transfer10's offsets would
  // decrypt this envelope into garbage.
  for (const i of Array(2).keys()) {
    assert.equal(p[22 + 2 * i], env.outputs[i].owner[0], `output ${i} owner.x at ${22 + 2 * i}`);
    assert.equal(p[23 + 2 * i], env.outputs[i].owner[1], `output ${i} owner.y at ${23 + 2 * i}`);
    assert.equal(p[26 + 2 * i], env.outputs[i].value, `output ${i} value at ${26 + 2 * i}`);
    assert.equal(p[27 + 2 * i], env.outputs[i].salt, `output ${i} salt at ${27 + 2 * i}`);
  }
});

test("transfer10x2 builder rejects wrong arity and a mismatched input owner in ANY slot", () => {
  const full = envFor("transfer10x2", 0);
  assert.throws(
    () => buildAuthorityPlaintext("transfer10x2", { inputs: full.inputs, outputs: [full.outputs[0]] }),
    /exactly 2 outputs/,
  );
  // The ten outputs of a transfer10 envelope are NOT a transfer10x2 envelope.
  assert.throws(
    () =>
      buildAuthorityPlaintext("transfer10x2", {
        inputs: full.inputs,
        outputs: envFor("transfer10", 0).outputs,
      }),
    /exactly 2 outputs/,
  );
  assert.throws(
    () => buildAuthorityPlaintext("transfer10x2", { inputs: full.inputs.slice(0, 4), outputs: full.outputs }),
    /exactly 10 inputs/,
  );
  // One circuit inputOwnerPrivateKey means input 7 cannot belong to someone else.
  const oddSlot: ParsedEnvelope = {
    inputs: full.inputs.map((n, i) => (i === 7 ? { ...n, owner: deriveKeypair(557007n).publicKey } : n)),
    outputs: full.outputs,
  };
  assert.throws(() => buildAuthorityPlaintext("transfer10x2", oddSlot), /share ONE owner/);
});

test("transfer10x2 fixture parity: both committed witness inputs agree with the sdk", () => {
  // circuits/fixtures/inputs/transfer10x2{,_merge}.json are what the committed proofs were
  // generated from: the partly-filled payment+change spend and the pure merge
  // (all ten inputs real, output 1 a ZERO change note).
  for (const fixture of ["transfer10x2", "transfer10x2_merge"]) {
    const inp = JSON.parse(
      readFileSync(join(ROOT, "circuits", "fixtures", "inputs", `${fixture}.json`), "utf8"),
    ) as Record<string, string[] | string[][] | string>;
    const arr = (k: string): bigint[] => (inp[k] as string[]).map(BigInt);
    const owners = (inp.outputOwnerPublicKeys as unknown as string[][]).map(
      (p) => [BigInt(p[0]), BigInt(p[1])] as Point,
    );

    const inValues = arr("inputValues");
    const outValues = arr("outputValues");
    const outSalts = arr("outputSalts");
    const enabled = arr("enabled");
    assert.equal(inValues.length, 10, `${fixture} spends ten slots`);
    assert.equal(outValues.length, 2, `${fixture} creates two notes`);

    const outCommits = arr("outputCommitments");
    for (const i of Array(2).keys()) {
      assert.equal(commitment(outValues[i], outSalts[i], owners[i]), outCommits[i], `${fixture} output ${i}`);
    }
    // conservation: CheckSum is an equality over all ten input slots, pads included.
    assert.equal(
      inValues.reduce((a, v) => a + v, 0n),
      outValues.reduce((a, v) => a + v, 0n),
      `${fixture} conserves value`,
    );
    // the §5.2 value belt on the fixture's own padding: enabled=0 ⟹ value=0.
    for (const i of Array(10).keys()) {
      if (enabled[i] === 0n) assert.equal(inValues[i], 0n, `${fixture} padded slot ${i} carries value 0`);
    }

    // The envelope over this fixture is the 30-field layout, and it round-trips.
    const inOwner = deriveKeypair(BigInt(inp.inputOwnerPrivateKey as string)).publicKey;
    const inSalts = arr("inputSalts");
    const env: ParsedEnvelope = {
      inputs: inValues.map((v, i) => ({ owner: inOwner, value: v, salt: inSalts[i] })),
      outputs: outValues.map((v, i) => ({ owner: owners[i], value: v, salt: outSalts[i] })),
    };
    const plain = buildAuthorityPlaintext("transfer10x2", env);
    assert.equal(plain.length, envelopePlaintextLen("transfer10x2", 0));
    const ecdhPriv = 717171717171717n;
    const nonce = BigInt(inp.encryptionNonce as string);
    const ct = poseidonEncrypt(plain, ecdhSharedSecret(ecdhPriv, AUTHORITY.publicKey), nonce);
    assert.equal(ct.length, authorityCiphertextLen("transfer10x2", 0));
    const parsed = parseEnvelope(
      AUTHORITY.formattedPrivateKey,
      deriveKeypair(ecdhPriv).publicKey,
      nonce,
      ct,
      "transfer10x2",
      0,
    );
    assert.deepEqual(parsed, env, `${fixture} envelope round-trips`);
  }
});

test("per-output nonces keep ten same-owner ciphertexts independent (§11-8 v1.1)", () => {
  // What the circuit relies on for duplicate output owners: ONE ephemeral key
  // and ten notes, each sponge keyed by encryptionNonce + i. Under the shared
  // nonce the notes would share a keystream; under nonce+i each opens only at
  // its own offset.
  const owner = deriveKeypair(554001n);
  const ecdhPriv = 626262626262626n;
  const shared = ecdhSharedSecret(ecdhPriv, owner.publicKey);
  const base = 909090909090n;
  const notes = Array.from({ length: 10 }, (_, i) => [500n + BigInt(i), 700n + BigInt(i)]);

  const cts = notes.map((n, i) => poseidonEncrypt(n, shared, base + BigInt(i)));
  notes.forEach((n, i) => {
    assert.deepEqual(poseidonDecrypt(cts[i], shared, base + BigInt(i), 2), n, `note ${i} at nonce+${i}`);
  });
  for (const i of Array.from({ length: 9 }, (_, j) => j + 1)) {
    assert.notDeepEqual(
      poseidonDecrypt(cts[i], shared, base, 2),
      notes[i],
      `note ${i} must NOT open under the un-offset nonce`,
    );
  }
});

test("kemPkFromSecret: the FIPS 203 dk embeds its ek at offset 1152", () => {
  // Pinned against noble's own keygen: the extracted slice must BE the
  // encapsulation key (byte-equal), and wrong-length keys are rejected —
  // parseKemKey callers rely on this to convict a truncated AUTHORITY_KEM_KEY
  // at boot instead of via false tamper alarms.
  const kp = ml_kem768.keygen(
    new Uint8Array([...shaBytes("bongtu/fixture/kem/seed/d"), ...shaBytes("bongtu/fixture/kem/seed/z")]),
  );
  assert.equal(kp.secretKey.length, KEM_SECRET_KEY_BYTES);
  assert.deepEqual(kemPkFromSecret(kp.secretKey), kp.publicKey);
  assert.throws(() => kemPkFromSecret(kp.publicKey), /2400 bytes/);
});
