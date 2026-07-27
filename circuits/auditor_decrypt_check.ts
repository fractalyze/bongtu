// §6b v2 auditor-decryptability gate (deliverable-defining, not optional).
//
// The product promise is ENFORCED AUDITOR DISCLOSURE: every note's creation
// (deposit) and destruction (withdraw) must be openable by the single arbiter
// key material from ON-CHAIN data alone. Post U-P1 the envelope key is HYBRID
// (pq-envelope-design.md §2): ECDH(BabyJubJub) || ML-KEM-768, folded through
// tagged Poseidon(5); the circuit additionally outputs
// kemBinding = Poseidon(3)([TAG_BIND, kemSs]). This script PROVES, end to end:
//
//   1. fresh witnesses (fresh ephemeral ecdh key + nonce + KEM encapsulation
//      per tx — SPEC §4 two-time-pad rule), groth16-proved (CPU snarkjs)
//      against the committed zkeys;
//   2. as the AUDITOR (holding ONLY the arbiter bjj private key + the ML-KEM
//      decapsulation key + what a chain carries: ecdhPublicKey, ciphertext,
//      nonce, kemBinding, kemCiphertext): Decaps the KEM ct, CHECK kemBinding,
//      derive the hybrid key, poseidon-decrypt, and assert the recovered
//      fields EQUAL the known plaintext;
//   3. NEGATIVES: a WRONG kemSs decrypts to garbage, and the LEGACY ECDH-only
//      key (the raw shared point) no longer decrypts a hybrid envelope;
//   4. FIXTURE envelopes: every committed fixture proof's envelope decrypts
//      (deposit/withdraw/transfer publics carry the ciphertext; the disburse
//      arities carry only kemBinding on-chain, so their KEM leg is checked via
//      binding == Poseidon(3) over the decapsulated limbs).
//
//   npx tsx auditor_decrypt_check.ts   # exits 0 iff all assertions hold
//
// Requires out/ from `bash prove_all.sh` (deposit/withdraw zkeys + wasm, plus
// the fixture *.public.json). Proving is CPU-only.
//
// DELIBERATELY HAND-ROLLED: this is the independent circuit-parity check, so
// the tag literals, limb encoding and hybrid-key fold below are restated here
// and must NOT be imported from @bongtu/core/kem or the envelope codec.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

import { ImtTree } from "@bongtu/core/imt";
import {
  deriveKeypair,
  commitment,
  nullifier,
  ecdhSharedSecret,
  poseidonDecrypt,
} from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import type { FieldInput } from "@bongtu/core/babyjub";
import { poseidonN } from "@bongtu/core/poseidon";
import { loadSnarkjs } from "@bongtu/core/extern";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "out");
const INPUTS = join(HERE, "inputs");
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = loadSnarkjs();

const H = 32;

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
}
function eq(a: FieldInput, b: FieldInput, msg: string): void {
  ok(BigInt(a) === BigInt(b), `${msg} (got ${a}, want ${b})`);
}
function strify(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(strify);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) o[k] = strify((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}
async function prove(name: string, input: unknown): Promise<bigint[]> {
  const wasm = join(OUT, `${name}_js`, `${name}.wasm`);
  const zkey = join(OUT, `${name}.zkey`);
  const { publicSignals } = await snarkjs.groth16.fullProve(strify(input), wasm, zkey);
  return (publicSignals as string[]).map((x) => BigInt(x));
}

// --- hand-rolled hybrid derivation (parity restatement of the circuits) -----

// sha256(ASCII) mod r — the frozen pq-envelope-design.md §2 literals.
const TAG_K0 = 10398998902367040515226727887904115149378422647845688990538198988921570667720n;
const TAG_K1 = 7025394518961265764175593663800963341053996587382265036146196548941915994055n;
const TAG_BIND = 5518019128667894418081277213291049553290157756968653594844689494754896839788n;

/** LE-uint128 limb pair from the 32-byte ML-KEM shared secret. */
function limbs(ss: Uint8Array): [bigint, bigint] {
  const le = (b: Uint8Array): bigint => {
    let v = 0n;
    for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]);
    return v;
  };
  return [le(ss.subarray(0, 16)), le(ss.subarray(16, 32))];
}
function hybridKey(ecdh: [bigint, bigint], ss: [bigint, bigint]): [bigint, bigint] {
  return [
    poseidonN([TAG_K0, ecdh[0], ecdh[1], ss[0], ss[1]]),
    poseidonN([TAG_K1, ecdh[0], ecdh[1], ss[0], ss[1]]),
  ];
}
const binding = (ss: [bigint, bigint]): bigint => poseidonN([TAG_BIND, ss[0], ss[1]]);

const sha256 = (label: string): Uint8Array =>
  new Uint8Array(createHash("sha256").update(label).digest());

// The single arbiter (auditor): bjj scalar + ML-KEM decapsulation key. Both are
// the fixture constants, restated locally (this file mirrors, never imports).
const AUTHORITY = deriveKeypair(555555555555555555555555n);
const AUTHORITY_KEM = ml_kem768.keygen(
  new Uint8Array([...sha256("bongtu/fixture/kem/seed/d"), ...sha256("bongtu/fixture/kem/seed/z")]),
);

/** Encapsulate to the arbiter KEM pk with label-derived randomness (PRNG-free). */
function encap(label: string): { kemSs: [bigint, bigint]; kemCiphertext: Uint8Array } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(
    AUTHORITY_KEM.publicKey,
    sha256(label),
  );
  return { kemSs: limbs(sharedSecret), kemCiphertext: cipherText };
}

/** The full arbiter-side KEM leg: Decaps(ct) -> limbs. */
function decap(kemCiphertext: Uint8Array): [bigint, bigint] {
  return limbs(ml_kem768.decapsulate(kemCiphertext, AUTHORITY_KEM.secretKey));
}

async function checkDeposit(): Promise<void> {
  console.log("\n=== DEPOSIT auditor-decrypt (outputs: 2 * (ownerPub, value, salt)) ===");
  const owner0 = deriveKeypair(31111111n);
  const owner1 = deriveKeypair(42222222n);
  const values = [1234n, 5678n];
  const salts = [900001n, 900002n];
  const oc = [
    commitment(values[0], salts[0], owner0.publicKey),
    commitment(values[1], salts[1], owner1.publicKey),
  ];
  // FRESH ephemeral ecdh key + nonce + KEM encapsulation for THIS tx (SPEC §4).
  const ecdhPrivateKey = 12121212121212121212121n;
  const encryptionNonce = 707070707070n;
  const kem = encap("bongtu/gate/kem/encap/deposit-fresh");

  const pub = await prove("deposit", {
    outputCommitments: oc,
    outputValues: values,
    outputSalts: salts,
    outputOwnerPublicKeys: [owner0.publicKey, owner1.publicKey],
    ecdhPrivateKey,
    kemSs: kem.kemSs,
    encryptionNonce,
    authorityPublicKey: AUTHORITY.publicKey,
  });
  ok(pub.length === 19, `deposit publics length == 19 (got ${pub.length})`);

  // chain-carried: ecdhPublicKey = pub[1..2]; ct = pub[3..12]; kemBinding = pub[13].
  const ecdhPublicKey: [bigint, bigint] = [pub[1], pub[2]];
  const cipherTextAuthority = pub.slice(3, 3 + 10);
  const kemBinding = pub[13];

  // AUDITOR: Decaps the (off-proof) KEM ct, check the binding, fold the hybrid key.
  const ssArb = decap(kem.kemCiphertext);
  eq(binding(ssArb), kemBinding, "kemBinding (pub[13]) == Poseidon(3)(TAG_BIND, Decaps limbs)");
  const ecdh = ecdhSharedSecret(AUTHORITY.formattedPrivateKey, ecdhPublicKey);
  const key = hybridKey([ecdh[0], ecdh[1]], ssArb);
  const m = poseidonDecrypt(cipherTextAuthority, key, encryptionNonce, 8);
  // plaintext layout: [own0.x, own0.y, own1.x, own1.y, val0, salt0, val1, salt1]
  eq(m[0], owner0.publicKey[0], "recovered output0 ownerPub.x");
  eq(m[1], owner0.publicKey[1], "recovered output0 ownerPub.y");
  eq(m[2], owner1.publicKey[0], "recovered output1 ownerPub.x");
  eq(m[3], owner1.publicKey[1], "recovered output1 ownerPub.y");
  eq(m[4], values[0], "recovered output0 value");
  eq(m[5], salts[0], "recovered output0 salt");
  eq(m[6], values[1], "recovered output1 value");
  eq(m[7], salts[1], "recovered output1 salt");
  // the recovered (value, salt, owner) reproduce the on-chain output commitments.
  eq(commitment(m[4], m[5], [m[0], m[1]]), oc[0], "recovered output0 rebuilds its on-chain commitment");
  eq(commitment(m[6], m[7], [m[2], m[3]]), oc[1], "recovered output1 rebuilds its on-chain commitment");

  // --- NEGATIVE (b): a WRONG kemSs cannot decrypt (garbage out) -------------
  const wrong = encap("bongtu/gate/kem/encap/deposit-WRONG");
  const mWrong = poseidonDecrypt(
    cipherTextAuthority,
    hybridKey([ecdh[0], ecdh[1]], wrong.kemSs),
    encryptionNonce,
    8,
  );
  ok(mWrong[0] !== owner0.publicKey[0], "WRONG kemSs: recovered field is garbage (no decrypt)");
  ok(
    commitment(mWrong[4], mWrong[5], [mWrong[0], mWrong[1]]) !== oc[0],
    "WRONG kemSs: garbage does NOT rebuild the on-chain commitment",
  );

  // --- NEGATIVE (c): the legacy ECDH-only key no longer decrypts ------------
  const mLegacy = poseidonDecrypt(cipherTextAuthority, ecdh, encryptionNonce, 8);
  ok(mLegacy[0] !== owner0.publicKey[0], "legacy ECDH-only key: recovered field is garbage");
  ok(
    commitment(mLegacy[4], mLegacy[5], [mLegacy[0], mLegacy[1]]) !== oc[0],
    "legacy ECDH-only key: garbage does NOT rebuild the on-chain commitment",
  );
}

// Insert commitments as single leaves; return root + per-leaf membership witness.
function membership(commitments: bigint[]): { root: bigint; pathElements: bigint[][]; leafIndices: bigint[] } {
  const tree = new ImtTree(H, 16);
  const idxs = commitments.map((c) => {
    const i = tree.getNextLeafIndex();
    tree.appendLeaf(c);
    return i;
  });
  const pathElements: bigint[][] = [];
  const leafIndices: bigint[] = [];
  for (const i of idxs) {
    pathElements.push(tree.merklePath(i).siblings);
    leafIndices.push(BigInt(i));
  }
  return { root: tree.getRoot(), pathElements, leafIndices };
}

async function checkWithdraw(): Promise<void> {
  console.log("\n=== WITHDRAW auditor-decrypt (inputOwner + 2*(inVal,inSalt) + change note) ===");
  const sender: Keypair = deriveKeypair(98765432109876n);
  const changeOwner = deriveKeypair(55550000n);
  const inValues = [600n, 500n];
  const inSalts = [800001n, 800002n];
  const inCommits = inValues.map((v, i) => commitment(v, inSalts[i], sender.publicKey));
  const { root, pathElements, leafIndices } = membership(inCommits);
  const outValue = 100n; // change; withdrawn amount out = 1100 - 100 = 1000
  const outSalt = 800003n;
  const outCommit = commitment(outValue, outSalt, changeOwner.publicKey);

  const ecdhPrivateKey = 34343434343434343434343n;
  const encryptionNonce = 818181818181n;
  const kem = encap("bongtu/gate/kem/encap/withdraw-fresh");

  const pub = await prove("withdraw", {
    nullifiers: inValues.map((v, i) => nullifier(v, inSalts[i], sender.formattedPrivateKey)),
    inputCommitments: inCommits,
    inputValues: inValues,
    inputSalts: inSalts,
    inputOwnerPrivateKey: sender.formattedPrivateKey,
    root,
    pathElements,
    leafIndices,
    enabled: [1n, 1n],
    outputCommitments: [outCommit],
    outputValues: [outValue],
    outputSalts: [outSalt],
    outputOwnerPublicKeys: [changeOwner.publicKey],
    ecdhPrivateKey,
    kemSs: kem.kemSs,
    encryptionNonce,
    authorityPublicKey: AUTHORITY.publicKey,
  });
  ok(pub.length === 26, `withdraw publics length == 26 (got ${pub.length})`);
  eq(pub[0], 1000n, "withdraw out (pub[0]) == 1100 - 100 == 1000");

  // chain-carried: ecdhPublicKey = pub[1..2]; ct = pub[3..15]; kemBinding = pub[16].
  const ecdhPublicKey: [bigint, bigint] = [pub[1], pub[2]];
  const cipherTextAuthority = pub.slice(3, 3 + 13);
  eq(binding(decap(kem.kemCiphertext)), pub[16], "kemBinding (pub[16]) == Poseidon(3)(TAG_BIND, Decaps limbs)");

  const ecdh = ecdhSharedSecret(AUTHORITY.formattedPrivateKey, ecdhPublicKey);
  const m = poseidonDecrypt(cipherTextAuthority, hybridKey([ecdh[0], ecdh[1]], decap(kem.kemCiphertext)), encryptionNonce, 10);
  // layout: [inOwner.x, inOwner.y, inVal0, inSalt0, inVal1, inSalt1, outOwner.x, outOwner.y, outVal0, outSalt0]
  eq(m[0], sender.publicKey[0], "recovered input owner pub.x");
  eq(m[1], sender.publicKey[1], "recovered input owner pub.y");
  eq(m[2], inValues[0], "recovered input0 value");
  eq(m[3], inSalts[0], "recovered input0 salt");
  eq(m[4], inValues[1], "recovered input1 value");
  eq(m[5], inSalts[1], "recovered input1 salt");
  eq(m[6], changeOwner.publicKey[0], "recovered change ownerPub.x");
  eq(m[7], changeOwner.publicKey[1], "recovered change ownerPub.y");
  eq(m[8], outValue, "recovered change value");
  eq(m[9], outSalt, "recovered change salt");
  // recovered input (value,salt,owner) reproduce the spent commitments; change rebuilds too.
  eq(commitment(m[2], m[3], [m[0], m[1]]), inCommits[0], "recovered input0 rebuilds its commitment");
  eq(commitment(m[4], m[5], [m[0], m[1]]), inCommits[1], "recovered input1 rebuilds its commitment");
  eq(commitment(m[8], m[9], [m[6], m[7]]), outCommit, "recovered change rebuilds its on-chain commitment");

  // --- NEGATIVE (c) on a spend: legacy ECDH-only key yields garbage ---------
  const mLegacy = poseidonDecrypt(cipherTextAuthority, ecdh, encryptionNonce, 10);
  ok(mLegacy[0] !== sender.publicKey[0], "legacy ECDH-only key: recovered field is garbage");
}

// --- FIXTURE envelopes (the committed prove_all.sh proofs) -------------------

const rd = (p: string): any => JSON.parse(readFileSync(p, "utf8"));

// Per-circuit fixture geometry: where the envelope lives in the publics, the
// plaintext length, and the fixture_lib kemDraw label (encap randomness).
const FIXTURES = [
  { name: "deposit", ctAt: 3, ctLen: 10, bindAt: 13, nPub: 19, plainLen: 8 },
  { name: "withdraw", ctAt: 3, ctLen: 13, bindAt: 16, nPub: 26, plainLen: 10 },
  { name: "transfer", ctAt: 10, ctLen: 16, bindAt: 26, nPub: 37, plainLen: 14 },
  { name: "disburse", ctAt: -1, ctLen: 0, bindAt: 4, nPub: 11, plainLen: 0 },
  { name: "disburse256", ctAt: -1, ctLen: 0, bindAt: 4, nPub: 11, plainLen: 0 },
] as const;

/** The fixture envelope plaintext, restated from the input json (hand-rolled
 *  layout mirror of the circuits, NOT the envelope codec). */
function fixturePlaintext(name: string, inp: any): bigint[] {
  const b = (x: FieldInput): bigint => BigInt(x);
  if (name === "deposit") {
    return [
      b(inp.outputOwnerPublicKeys[0][0]), b(inp.outputOwnerPublicKeys[0][1]),
      b(inp.outputOwnerPublicKeys[1][0]), b(inp.outputOwnerPublicKeys[1][1]),
      b(inp.outputValues[0]), b(inp.outputSalts[0]),
      b(inp.outputValues[1]), b(inp.outputSalts[1]),
    ];
  }
  // spend layout: [inOwner, (inVal,inSalt)*nIn, (outOwner)*nOut, (outVal,outSalt)*nOut]
  const inOwner = deriveKeypair(BigInt(inp.inputOwnerPrivateKey)).publicKey;
  const out: bigint[] = [inOwner[0], inOwner[1]];
  for (let i = 0; i < inp.inputValues.length; i++) out.push(b(inp.inputValues[i]), b(inp.inputSalts[i]));
  for (const o of inp.outputOwnerPublicKeys) out.push(b(o[0]), b(o[1]));
  for (let i = 0; i < inp.outputValues.length; i++) out.push(b(inp.outputValues[i]), b(inp.outputSalts[i]));
  return out;
}

async function checkFixtureEnvelopes(): Promise<void> {
  console.log("\n=== FIXTURE envelopes (out/*.public.json from prove_all.sh + GPU run) ===");
  for (const f of FIXTURES) {
    const pubPath = join(OUT, `${f.name}.public.json`);
    if (!existsSync(pubPath)) {
      console.log(`   SKIP  ${f.name}: ${pubPath} missing (not proved in this run)`);
      continue;
    }
    const pub = (rd(pubPath) as string[]).map((x) => BigInt(x));
    const inp = rd(join(INPUTS, `${f.name}.json`));
    ok(pub.length === f.nPub, `${f.name}: publics length == ${f.nPub} (got ${pub.length})`);

    // The arbiter-side KEM leg: recompute the fixture ct (label-derived encap
    // randomness == fixture_lib.kemDraw), Decaps it, check the public binding.
    const kem = encap(`bongtu/fixture/kem/encap/${f.name}`);
    const ssArb = decap(kem.kemCiphertext);
    eq(binding(ssArb), pub[f.bindAt], `${f.name}: kemBinding (pub[${f.bindAt}]) == binding(Decaps limbs)`);

    if (f.ctAt < 0) {
      console.log(`   note  ${f.name}: envelope ct is off-chain (disclosureHash-bound), KEM leg checked via binding`);
      continue;
    }
    const ct = pub.slice(f.ctAt, f.ctAt + f.ctLen);
    const ecdhPub: [bigint, bigint] = f.name === "transfer" ? [pub[0], pub[1]] : [pub[1], pub[2]];
    const ecdh = ecdhSharedSecret(AUTHORITY.formattedPrivateKey, ecdhPub);
    const m = poseidonDecrypt(ct, hybridKey([ecdh[0], ecdh[1]], ssArb), BigInt(inp.encryptionNonce), f.plainLen);
    const want = fixturePlaintext(f.name, inp);
    let all = true;
    for (let i = 0; i < want.length; i++) all = all && m[i] === want[i];
    ok(all, `${f.name}: FULL envelope decrypt matches all ${want.length} plaintext fields`);
  }
}

async function main(): Promise<void> {
  await checkDeposit();
  await checkWithdraw();
  await checkFixtureEnvelopes();
  console.log(
    `\n${failures === 0
      ? "AUDITOR-DECRYPT GATE: PASS — hybrid (ECDH||ML-KEM) envelopes are recoverable by the arbiter key material alone; wrong-kemSs and legacy-ECDH decrypts fail"
      : `AUDITOR-DECRYPT GATE: FAIL — ${failures} assertion(s)`}`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nAUDITOR-DECRYPT ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
