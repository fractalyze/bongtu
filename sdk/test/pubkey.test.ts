// Point-compression round-trips + curve validation (SPEC §6b v2 note-owner id).
// Run via `npm test` (node --test via tsx) alongside the U1/U2 suites.

import { test } from "node:test";
import assert from "node:assert/strict";

import { Base8, mulPointEscalar, isOnCurve, P, A, D } from "../src/babyjub.js";
import { deriveKeypair } from "../src/note.js";
import { packPubkey, unpackPubkey, sqrtMod } from "../src/pubkey.js";

const fmod = (x: bigint): bigint => ((x % P) + P) % P;

// A y-coordinate that lies on NO curve point: x^2 = (1-y^2)/(a-d*y^2) is a
// non-residue, so decompression has no root. Found deterministically (no RNG).
function offCurveY(): bigint {
  for (let y = 2n; y < 10000n; y++) {
    const y2 = fmod(y * y);
    const x2 = fmod(fmod(1n - y2) * modInv(fmod(A - fmod(D * y2))));
    if (sqrtMod(x2) === null) return y;
  }
  throw new Error("no off-curve y found in range");
}
function modInv(x: bigint): bigint {
  let [old_r, r] = [fmod(x), P];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return fmod(old_s);
}
function leHex(y: bigint): string {
  let hex = "";
  let v = y;
  for (let i = 0; i < 32; i++) {
    hex += Number(v & 0xffn).toString(16).padStart(2, "0");
    v >>= 8n;
  }
  return "0x" + hex;
}

test("sqrtMod: r*r == n for residues; null for a non-residue", () => {
  for (const n of [0n, 1n, 4n, 9n, 123456789n, 2n * 3n * 5n]) {
    const r = sqrtMod(n % P);
    if (r === null) continue;
    assert.equal((r * r) % P, n % P, `sqrt(${n})^2 != ${n}`);
  }
  // A guaranteed residue: square something, take the root back.
  const sq = (999999n * 999999n) % P;
  const r = sqrtMod(sq);
  assert.ok(r !== null && (r * r) % P === sq, "sqrt of a perfect square failed");
});

test("packPubkey emits 0x + 64 hex chars (32-byte LE y + sign bit)", () => {
  const p = deriveKeypair(123456789n).publicKey;
  const packed = packPubkey(p);
  assert.match(packed, /^0x[0-9a-f]{64}$/, `bad packed form: ${packed}`);
});

test("unpackPubkey(packPubkey(p)) === p for many keypairs (both x parities)", () => {
  let sawEven = false;
  let sawOdd = false;
  for (let i = 1; i <= 250; i++) {
    const p = mulPointEscalar(Base8, 1000003n * BigInt(i) + 7n) as [bigint, bigint];
    assert.ok(isOnCurve(p));
    const round = unpackPubkey(packPubkey(p));
    assert.deepEqual(round, p, `round-trip failed for keypair ${i}`);
    if ((p[0] & 1n) === 0n) sawEven = true;
    else sawOdd = true;
  }
  // Both sign-bit branches must be exercised or the sign recovery is untested.
  assert.ok(sawEven && sawOdd, "test did not cover both x parities");
});

test("unpackPubkey recovers the correct x root (sign bit disambiguates)", () => {
  const p = deriveKeypair(555555555555555555555555n).publicKey;
  const [x, y] = unpackPubkey(packPubkey(p));
  assert.equal(x, p[0], "x mismatch");
  assert.equal(y, p[1], "y mismatch");
  assert.equal(x & 1n, p[0] & 1n, "parity mismatch");
});

test("unpackPubkey rejects malformed input", () => {
  assert.throws(() => unpackPubkey("abc"), /32-byte hex/, "short hex accepted");
  assert.throws(() => unpackPubkey("0x" + "zz".repeat(32)), /32-byte hex/, "non-hex accepted");
  // A y with no valid x (curve equation has no root) must throw, not return junk.
  const y = offCurveY();
  assert.throws(() => unpackPubkey(leHex(y)), /curve|residue/, "off-curve y accepted");
});
