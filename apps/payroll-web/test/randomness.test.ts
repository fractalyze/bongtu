// Recipient-count privacy: the disburse batch pads real recipients up to B with
// zero-value dummy notes to hide HOW MANY reals there are. That padding only
// hides the count if an observer cannot recompute it. Previously the ephemeral
// ECDH key, encryption nonce, output salts, and pad owner keys were hardcoded /
// deterministic (seed + i), so an observer who assumed the defaults could
// recompute every pad key, trial-decrypt the on-chain `Disbursed` ciphertext,
// and recover the real count (and the plaintext). And the slot layout was
// real -> change -> pads, so slot i leaked N >= i+1.
//
// These tests assert the fix: every count-hiding value is drawn FRESH from the
// CSPRNG per batch (default entropy) and the slots are shuffled, so building the
// SAME recipient list twice shares NO constant and puts a given recipient at a
// different slot.

import { test } from "node:test";
import assert from "node:assert/strict";

import { deriveKeypair, commitment } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { ImtTree } from "@bongtu/core/imt";
import { ml_kem768, kemSsToLimbs, kemHexToBytes, kemBytesToHex } from "@bongtu/core/kem";
import { ARBITER_KEM_PK } from "@bongtu/core/network";
import { buildDisburseRequest, type RecipientRow } from "../src/lib/disburse.js";
import { DEFAULTS, H, B } from "../src/config.js";

// A real KEM encapsulation (fixed randomness) — the KEM half is out of scope for
// these tests; we hold it constant so ONLY the CSPRNG-drawn ecdh/nonce/salt/pad/
// shuffle vary between the two builds.
const ENCAP = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK), new Uint8Array(32).fill(9));
const FIXED_KEM = {
  kemSs: kemSsToLimbs(ENCAP.sharedSecret).map(String) as [string, string],
  kemCiphertext: kemBytesToHex(ENCAP.cipherText),
};

const EMPLOYER = deriveKeypair(313131313131313131313131n);
const RECIP0_SCALAR = 4000000019n; // recipient #1's derivation scalar (see below)

// A 3-recipient batch; the crypto object carries ONLY the public arbiter key + the
// fixed KEM. All the randomized material comes from buildDisburseRequest's default
// CSPRNG entropy — no injected double here, so each call is genuinely fresh.
function build() {
  const value = 100000n;
  const inSalt = 777n;
  const inCommit = commitment(value, inSalt, EMPLOYER.publicKey);
  const tree = new ImtTree(H, B);
  tree.appendLeaf(commitment(1n, 1n, EMPLOYER.publicKey));
  tree.appendLeaf(inCommit);
  const { siblings } = tree.merklePath(1);
  const recipients: RecipientRow[] = Array.from({ length: 3 }, (_, i) => {
    const kp = deriveKeypair(RECIP0_SCALAR + BigInt(i) * 1000003n);
    return { pubkey: packPubkey(kp.publicKey), amount: (100n + BigInt(i)).toString() };
  });
  const inputNote = {
    value: value.toString(),
    salt: inSalt.toString(),
    ownerPrivateKey: EMPLOYER.formattedPrivateKey.toString(),
  };
  const membership = { root: tree.getRoot().toString(), pathElements: siblings.map(String), leafIndex: 1 };
  const crypto = { authorityPubKey: DEFAULTS.arbiterPubKey, kemSs: FIXED_KEM.kemSs, kemCiphertext: FIXED_KEM.kemCiphertext };
  return buildDisburseRequest(inputNote, membership, recipients, crypto);
}

// Indices of the zero-value (pad) slots, as "x,y" owner keys, sorted — an
// order-independent view of the dummy pad key SET.
function padOwnerSet(inp: {
  outputValues: string[];
  outputOwnerPublicKeys: [string, string][];
}): string[] {
  return inp.outputValues
    .map((v, i) => (v === "0" ? `${inp.outputOwnerPublicKeys[i][0]},${inp.outputOwnerPublicKeys[i][1]}` : null))
    .filter((x): x is string => x !== null)
    .sort();
}

// The slots holding a real (non-zero) value, in slot order — a fingerprint of the
// shuffle.
function realSlotPositions(outputValues: string[]): number[] {
  return outputValues.map((v, i) => (v === "0" ? -1 : i)).filter((i) => i >= 0);
}

// Each build does 256 pure-JS scalar-mults (pad keys + per-output ECDH), ~30s. So
// build a SMALL shared set once and drive both tests off it rather than re-building.
interface Inp {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  outputSalts: string[];
  outputValues: string[];
  outputOwnerPublicKeys: [string, string][];
}
const BATCHES: Inp[] = [build(), build(), build()].map((r) => r.request.input as unknown as Inp);

test("two batches of the SAME recipient list share NO constant (fresh CSPRNG per batch)", () => {
  const [a, b] = BATCHES;

  // 1. ephemeral ECDH private key is fresh (was the constant 900000000000000000007).
  assert.notEqual(a.ecdhPrivateKey, b.ecdhPrivateKey, "ecdhPrivateKey must differ per batch");

  // 2. encryption nonce is fresh (was the constant 424242424243).
  assert.notEqual(a.encryptionNonce, b.encryptionNonce, "encryptionNonce must differ per batch");

  // 3. output salts are fresh (were sequential saltSeed + i — fully recomputable).
  assert.notDeepEqual(a.outputSalts, b.outputSalts, "output salts must differ per batch");
  // and not sequential within a single batch either (no +1 stride to exploit).
  const s = a.outputSalts.map(BigInt);
  const sequential = s.every((v, i) => i === 0 || v === s[i - 1] + 1n);
  assert.equal(sequential, false, "salts must not be a sequential run");

  // 4. pad owner keys are fresh random (were deriveKeypair(padSeed + i*1000003 + 1)).
  assert.notDeepEqual(padOwnerSet(a), padOwnerSet(b), "pad owner pubkeys must differ per batch");

  // 5. the slot order (positions of the real notes) is shuffled differently.
  assert.notDeepEqual(
    realSlotPositions(a.outputValues),
    realSlotPositions(b.outputValues),
    "shuffled slot order must differ per batch",
  );

  // sanity: both are still valid 256-output batches conserving value.
  for (const inp of [a, b]) {
    assert.equal(inp.outputValues.length, B);
    assert.equal(
      inp.outputValues.reduce((acc, v) => acc + BigInt(v), 0n),
      100000n,
    );
  }
});

test("a known recipient lands at a DIFFERENT slot across runs (shuffle is real)", () => {
  const target = deriveKeypair(RECIP0_SCALAR).publicKey; // recipient #1's owner point
  const key = `${target[0]},${target[1]}`;
  const slots = BATCHES.map((inp) => {
    const idx = inp.outputOwnerPublicKeys.findIndex((p) => `${BigInt(p[0])},${BigInt(p[1])}` === key);
    assert.ok(idx >= 0, "the known recipient must appear in the batch");
    return idx;
  });
  // Without a shuffle this recipient would be pinned at slot 0 every run. With the
  // Fisher-Yates shuffle over B=256 slots, all 3 runs landing on one identical index
  // is astronomically unlikely (~256^-2), so distinct positions prove the shuffle.
  assert.ok(new Set(slots).size > 1, `recipient slot never moved across runs: ${slots.join(",")}`);
});

test("the encryption nonce fits the circuit's 128-bit slot under REAL entropy", () => {
  // Regression for the a40f1c6 nonce bug: the CSPRNG draw is a full field element
  // (< 2^248), but SymmetricEncrypt packs the nonce with messageLength into ONE
  // Poseidon slot and constrains nonce < 2^128 — an unclamped draw made witness
  // generation fail with probability ~1-2^-120, i.e. every real pay run. The
  // seeded-double tests can never catch this (their generator masks to 128 bits
  // by construction), so the assert runs on the default-entropy batches.
  for (const inp of BATCHES) {
    const n = BigInt(inp.encryptionNonce);
    assert.ok(n >= 0n && n < 1n << 128n, `nonce ${n} exceeds the 128-bit circuit slot`);
  }
});
