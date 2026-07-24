// U2 support: note/key/crypto machinery + the SPEC §4 / §11-8 dup-owner guard.
// Run via `npm test` (node --test via tsx) alongside the U1 IMT suite.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Base8, mulPointEscalar, addPoint, isOnCurve } from "../src/babyjub.js";
import {
  deriveKeypair,
  commitment,
  nullifier,
  poseidonEncrypt,
  poseidonDecrypt,
  ecdhSharedSecret,
  assertDistinctOwnerPubkeys,
} from "../src/note.js";

// --- babyjub self-checks (no external reference; on-curve + ladder consistency)

test("babyjub: Base8 and its multiples stay on the curve", () => {
  assert.ok(isOnCurve(Base8));
  for (const k of [1n, 2n, 3n, 7n, 123456789n]) {
    assert.ok(isOnCurve(mulPointEscalar(Base8, k)), `k=${k} off curve`);
  }
});

test("babyjub: ladder agrees with repeated addition (2P,3P) and 1*P==P", () => {
  assert.deepEqual(mulPointEscalar(Base8, 1n), Base8);
  const twoP = addPoint(Base8, Base8);
  assert.deepEqual(mulPointEscalar(Base8, 2n), twoP);
  const threeP = addPoint(twoP, Base8);
  assert.deepEqual(mulPointEscalar(Base8, 3n), threeP);
});

test("babyjub: ECDH is symmetric — a*(b*G) == b*(a*G)", () => {
  const a = deriveKeypair(11111111n);
  const b = deriveKeypair(22222222n);
  assert.deepEqual(
    ecdhSharedSecret(a.formattedPrivateKey, b.publicKey),
    ecdhSharedSecret(b.formattedPrivateKey, a.publicKey),
  );
});

// --- Poseidon-sponge cipher round-trips (byte-compatible with encrypt.circom) --

test("poseidonEncrypt/Decrypt round-trips a value/salt pair", () => {
  const a = deriveKeypair(11111111n);
  const b = deriveKeypair(22222222n);
  const key = ecdhSharedSecret(a.formattedPrivateKey, b.publicKey);
  const msg = [4242n, 1000001n];
  const ct = poseidonEncrypt(msg, key, 424242n);
  assert.equal(ct.length, 4); // pad3(2)=3 -> 3 + 1
  assert.deepEqual(poseidonDecrypt(ct, key, 424242n, 2), msg);
});

// --- commitment / nullifier shape ------------------------------------------

test("commitment and nullifier are deterministic field elements", () => {
  const kp = deriveKeypair(33333333n);
  const c = commitment(500n, 777n, kp.publicKey);
  const n = nullifier(500n, 777n, kp.formattedPrivateKey);
  assert.equal(typeof c, "bigint");
  assert.equal(typeof n, "bigint");
  assert.notEqual(c, n);
});

// --- the dup-owner guard (the gated behavior) ------------------------------

test("assertDistinctOwnerPubkeys accepts distinct receivers", () => {
  const owners = [0, 1, 2].map((i) => deriveKeypair(100000n + BigInt(i) * 7n).publicKey);
  assert.doesNotThrow(() => assertDistinctOwnerPubkeys(owners));
});

test("assertDistinctOwnerPubkeys REJECTS a duplicated output owner pubkey", () => {
  const dup = deriveKeypair(424242n).publicKey;
  const other = deriveKeypair(999n).publicKey;
  assert.throws(
    () => assertDistinctOwnerPubkeys([dup, other, dup]),
    /duplicate output owner pubkey/,
  );
});
